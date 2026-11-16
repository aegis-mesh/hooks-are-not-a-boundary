#!/usr/bin/env bash
# Capture the kernel's view with Endpoint Security (eslogger) while the agent
# simulator runs, then attribute every credential access back to the agent.
# REQUIRES: a normal Terminal with Full Disk Access, and sudo (eslogger is root).
set -uo pipefail
LAB="${1:?usage: os_capture.sh <lab> <kit> <out>}"
KIT="${2:?}"; OUT="${3:?}"
PORT="${PORT:-8099}"
mkdir -p "$OUT/os"
EV="$OUT/os/events.jsonl"

command -v eslogger >/dev/null || { echo "eslogger not found (needs macOS 12+)"; exit 1; }

echo "This needs sudo (eslogger runs as root) and Full Disk Access on this terminal."
sudo -v || { echo "sudo required"; exit 1; }

# local server to receive the (fake) key
python3 "$LAB/server/listener.py" >/dev/null 2>&1 & SRV=$!
sleep 1

# start the kernel capture (exec+fork+open), one JSON object per line
sudo eslogger exec fork open >"$EV" 2>"$OUT/os/eslogger.err" &
sleep 2
ESL=$(pgrep -n eslogger)

# run the agent simulation; record its pid
bash "$KIT/os/agent_sim.sh" "$LAB" "$OUT/os/agent.pid"
sleep 5   # let the re-parented background job fire

sudo kill "$ESL" 2>/dev/null
kill "$SRV" 2>/dev/null
sleep 1

AGENT=$(cat "$OUT/os/agent.pid" 2>/dev/null || echo 0)
echo "agent pid: $AGENT   kernel events captured: $(wc -l <"$EV" | tr -d ' ')"
echo
echo "== first events (schema calibration) =="
python3 "$KIT/os/lineage.py" "$EV" --probe | head -40 >"$OUT/os/schema-probe.txt"
echo "   (saved to $OUT/os/schema-probe.txt)"
echo
echo "== attribution =="
python3 "$KIT/os/lineage.py" "$EV" --agent-pid "$AGENT" | tee "$OUT/os/attribution.txt"
echo
echo "server receipts:"; grep "key=YES" "$LAB/server/received.log" 2>/dev/null | sed 's/  */ /g' || echo "(none)"
echo "raw events: $EV"
