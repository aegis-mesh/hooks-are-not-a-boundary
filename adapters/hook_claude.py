#!/usr/bin/env python3
"""Claude Code PreToolUse adapter.

Reads the PreToolUse JSON Claude Code sends on stdin, normalises it to a policy
action, and emits Claude Code's decision schema. Deny is expressed both as the
documented hookSpecificOutput.permissionDecision="deny" and as exit code 2, so
the decision is unambiguous whichever the runtime honours.

Contract (Claude Code hooks reference):
  stdin:  {"tool_name": "Bash"|"Read"|..., "tool_input": {...}, ...}
  stdout: {"hookSpecificOutput": {"hookEventName":"PreToolUse",
            "permissionDecision":"allow"|"deny", "permissionDecisionReason": "..."}}
  exit:   0 allow, 2 deny.
"""
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "policy"))
from guard_core import decide, audit  # noqa: E402


def normalise(payload: dict) -> dict:
    tool = (payload.get("tool_name") or "").lower()
    ti = payload.get("tool_input") or {}
    if tool in ("bash", "shell") or "command" in ti:
        return {"kind": "exec", "command": ti.get("command", "")}
    if tool in ("write", "edit") or ("content" in ti and ("file_path" in ti or "path" in ti)):
        return {"kind": "write", "path": ti.get("file_path") or ti.get("path", ""),
                "content": ti.get("content", "")}
    if tool in ("read", "readfile") or "file_path" in ti:
        return {"kind": "read", "path": ti.get("file_path") or ti.get("path", "")}
    # A tool the policy has no view into (MCP, Task...).
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
    audit("claude", result["decision"], action)
    reason = result["rule"] or "no matching rule"
    print(json.dumps({"hookSpecificOutput": {
        "hookEventName": "PreToolUse",
        "permissionDecision": result["decision"],
        "permissionDecisionReason": reason,
    }}))
    return 2 if result["decision"] == "deny" else 0


if __name__ == "__main__":
    sys.exit(main())
