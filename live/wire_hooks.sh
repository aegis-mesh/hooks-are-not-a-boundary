#!/usr/bin/env bash
# Wire each agent's REAL hook into the lab project, all pointing at the shared
# policy via that agent's adapter. Paths must be space-free (the bundle copies
# the kit under a space-free path for this reason). HOOKLAB_AUDIT is inherited from
# the shell that launches the agent, so every decision is logged independently.
set -euo pipefail
LAB="${1:?usage: wire_hooks.sh <lab> <kit>}"
KIT="${2:?usage: wire_hooks.sh <lab> <kit>}"
P="$LAB/project"
A="$KIT/adapters"

mkdir -p "$P/.claude" "$P/.cursor" "$P/.codex"

# --- Claude Code: PreToolUse on every tool ----------------------------------
cat >"$P/.claude/settings.json" <<EOF
{
  "hooks": {
    "PreToolUse": [
      { "matcher": "*",
        "hooks": [ { "type": "command", "command": "python3 $A/hook_claude.py" } ] }
    ]
  }
}
EOF

# --- Cursor: the three permission hooks -------------------------------------
cat >"$P/.cursor/hooks.json" <<EOF
{
  "version": 1,
  "hooks": {
    "beforeShellExecution": [ { "command": "python3 $A/hook_cursor.py", "timeout": 10 } ],
    "beforeReadFile":       [ { "command": "python3 $A/hook_cursor.py", "timeout": 10 } ],
    "preToolUse":           [ { "command": "python3 $A/hook_cursor.py", "timeout": 10 } ]
  }
}
EOF

# --- Codex: PreToolUse (matcher *) ------------------------------------------
cat >"$P/.codex/hooks.json" <<EOF
{
  "description": "hooklab",
  "hooks": {
    "PreToolUse": [
      { "matcher": "*",
        "hooks": [ { "type": "command", "command": "python3 $A/hook_codex.py" } ] }
    ]
  }
}
EOF

# validate the JSON we just wrote
for f in "$P/.claude/settings.json" "$P/.cursor/hooks.json" "$P/.codex/hooks.json"; do
  python3 -c "import json,sys; json.load(open(sys.argv[1]))" "$f" || { echo "BAD JSON: $f"; exit 1; }
done
echo "hooks wired for claude, cursor, codex in $P"
