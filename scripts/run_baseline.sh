#!/usr/bin/env bash
set -u
STAGING="$1"; MANIFEST="$2"; OUTDIR="$3"; PAR="${4:-4}"; TIER="${5:-tier1}"
export PY="${PY:-python3}"
export STAGING OUTDIR TIER
mkdir -p "$OUTDIR" "$OUTDIR/logs"
cd "$(dirname "$0")/.."   # repository root
run_one(){ local n="$1"; [ -f "$OUTDIR/$n.json" ] && return 0
  "$PY" scripts/baseline_one.py "$STAGING/$n" "$OUTDIR/$n.json" "$TIER" > "$OUTDIR/logs/$n.log" 2>&1; }
export -f run_one
tail -n +2 "$MANIFEST" | cut -d, -f1 | xargs -P "$PAR" -I {} bash -c 'run_one "$@"' _ {}
echo DONE
