#!/usr/bin/env bash
# One command to build the lab and run the parts you ask for. Copies the kit to a
# space-free output dir, builds the lab, and runs what you select. Run from a
# normal Terminal with Full Disk Access; the OS capture will ask for sudo.
# Output lands under $OUT for analysis.
#
#   bash run_bundle.sh                 # everything (deterministic + live + os + sandbox)
#   bash run_bundle.sh --os --sandbox  # just the parts that need this terminal
#   bash run_bundle.sh --live          # just the live agent replication
set -uo pipefail
SRC="$(cd "$(dirname "$0")" && pwd)"
STAMP="$(date +%Y%m%d-%H%M)"
OUT="${OUT:-$HOME/hooklab-out/hooklab-$STAMP}"
DO_DET=0; DO_LIVE=0; DO_OS=0; DO_SBX=0
if [ $# -eq 0 ]; then DO_DET=1; DO_LIVE=1; DO_OS=1; DO_SBX=1; fi
for a in "$@"; do case "$a" in
  --all) DO_DET=1; DO_LIVE=1; DO_OS=1; DO_SBX=1;;
  --deterministic) DO_DET=1;; --live) DO_LIVE=1;; --os) DO_OS=1;; --sandbox) DO_SBX=1;;
  *) echo "unknown flag: $a"; exit 1;; esac; done

mkdir -p "$OUT"
KIT="$OUT/kit"
echo "== copying kit to space-free path =="
rm -rf "$KIT"; cp -R "$SRC" "$KIT"
LAB="$OUT/lab"
echo "== building lab =="
bash "$KIT/setup_lab.sh" "$LAB" | tail -1
bash "$KIT/live/wire_hooks.sh" "$LAB" "$KIT" | tail -1

[ "$DO_DET" = 1 ] && { echo; echo "######## DETERMINISTIC MATRIX ########";
  python3 "$KIT/drivers/run_matrix.py" "$LAB" | tee "$OUT/matrix.txt"; }

[ "$DO_LIVE" = 1 ] && { echo; echo "######## LIVE REPLICATION (uses your agent accounts) ########";
  bash "$KIT/live/run_live.sh" "$LAB" "$KIT" "$OUT"; }

[ "$DO_OS" = 1 ] && { echo; echo "######## OS ATTRIBUTION (sudo + Full Disk Access) ########";
  bash "$KIT/os/os_capture.sh" "$LAB" "$KIT" "$OUT"; }

[ "$DO_SBX" = 1 ] && { echo; echo "######## CODEX SANDBOX AXIS ########";
  bash "$KIT/sandbox/sandbox_axis.sh" "$LAB" "$KIT" "$OUT"; }

echo; echo "== done. evidence under: $OUT =="
find "$OUT" -maxdepth 2 -type f \( -name '*.csv' -o -name '*.txt' -o -name '*.jsonl' \) | sort
echo
echo "Tell Claude: the evidence is in $OUT"
