#!/usr/bin/env python3
"""Codex PreToolUse adapter.

Reads the Codex PreToolUse JSON, normalises it, and emits Codex's deny schema
(permissionDecision="deny") plus exit code 2, both documented ways to block a
tool call. On allow it exits 0 with no decision, letting the call proceed.

Contract (Codex hooks docs):
  stdin:  {"tool_name": "...", "tool_use_id": "...", "tool_input": {...},
           "hook_event_name":"PreToolUse", "session_id","cwd","model",...}
  stdout (deny): {"permissionDecision": "deny", "reason": "..."}
                 (legacy {"decision":"block"} and exit 2 also block)
  Fail-open: a PreToolUse error, timeout, or malformed response can let the
  tool run (per Codex docs).
"""
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "policy"))
from guard_core import decide, audit  # noqa: E402


def normalise(payload: dict) -> dict:
    tool = (payload.get("tool_name") or "").lower()
    ti = payload.get("tool_input") or {}
    # Codex shell tool input commonly carries a command string or argv list.
    if tool in ("bash", "shell", "local_shell", "exec") or "command" in ti:
        cmd = ti.get("command", "")
        if isinstance(cmd, list):
            cmd = " ".join(str(x) for x in cmd)
        return {"kind": "exec", "command": cmd}
    if tool in ("write", "write_file", "apply_patch") or ("content" in ti and ("path" in ti or "file_path" in ti)):
        return {"kind": "write", "path": ti.get("path") or ti.get("file_path", ""),
                "content": ti.get("content", "")}
    if tool in ("read", "read_file") or "path" in ti or "file_path" in ti:
        return {"kind": "read", "path": ti.get("path") or ti.get("file_path", "")}
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
    audit("codex", result["decision"], action)
    if result["decision"] == "deny":
        print(json.dumps({"permissionDecision": "deny",
                          "reason": f"blocked by policy: {result['rule']}"}))
        return 2
    # allow: no decision, proceed
    print(json.dumps({}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
