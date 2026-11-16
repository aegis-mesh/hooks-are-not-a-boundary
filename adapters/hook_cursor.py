#!/usr/bin/env python3
"""Cursor agent-hook adapter.

Handles the three Cursor permission hooks that can deny an action:
beforeShellExecution, beforeReadFile, and the generic preToolUse. Emits Cursor's
decision schema {"permission": "allow"|"deny"}. Exit 0 so Cursor reads the JSON;
Cursor also treats exit 2 as deny, which we add for an unambiguous block.

Contract (Cursor agent hooks docs):
  beforeShellExecution stdin: {"command": "...", "cwd": "...", "sandbox": "..."}
  beforeReadFile       stdin: {"file_path": "...", "content": "..."}
  preToolUse           stdin: {"tool_name": "...", "tool_input": {...}}
  stdout: {"permission": "allow"|"deny", "agent_message": "..."}
  Fail-open default: on crash/timeout/other exit, Cursor proceeds.
"""
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "policy"))
from guard_core import decide, audit  # noqa: E402


def normalise(payload: dict) -> dict:
    event = payload.get("hook_event_name") or ""
    # beforeShellExecution
    if "command" in payload or event == "beforeShellExecution":
        return {"kind": "exec", "command": payload.get("command", "")}
    # beforeReadFile
    if "file_path" in payload or event == "beforeReadFile":
        return {"kind": "read", "path": payload.get("file_path", "")}
    # preToolUse (generic)
    ti = payload.get("tool_input") or {}
    tool = (payload.get("tool_name") or "").lower()
    if tool in ("shell", "bash") or "command" in ti:
        return {"kind": "exec", "command": ti.get("command", "")}
    if tool in ("write", "edit") or ("content" in ti and ("file_path" in ti or "path" in ti)):
        return {"kind": "write", "path": ti.get("file_path") or ti.get("path", ""),
                "content": ti.get("content", "")}
    if tool in ("read", "readfile") or "file_path" in ti:
        return {"kind": "read", "path": ti.get("file_path") or ti.get("path", "")}
    return {"kind": "other", "tool": tool}


def main() -> int:
    try:
        payload = json.loads(sys.stdin.read() or "{}")
    except Exception:
        payload = {}
    action = normalise(payload)
    if action["kind"] == "other":
        result = {"decision": "allow", "rule": "tool-not-inspected"}
    else:
        result = decide(action)
    audit("cursor", result["decision"], action)
    out = {"permission": result["decision"]}
    if result["decision"] == "deny":
        out["agent_message"] = f"blocked by policy: {result['rule']}"
    print(json.dumps(out))
    return 2 if result["decision"] == "deny" else 0


if __name__ == "__main__":
    sys.exit(main())
