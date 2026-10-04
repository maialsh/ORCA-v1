#!/usr/bin/env bash
set -u
STAGING="$1"; MANIFEST="$2"; OUTDIR="$3"; PAR="${4:-4}"; TIER="${5:-tier1}"
export PY=/Users/maitha/.local/share/virtualenvs/ORCA-w1m1Q-95/bin/python
export STAGING OUTDIR TIER
mkdir -p "$OUTDIR" "$OUTDIR/logs"
cd /Users/maitha/Desktop/Manuscript2_ORCA/ORCA
run_one(){ local n="$1"; [ -f "$OUTDIR/$n.json" ] && return 0
  "$PY" dry_runs/full_run/baseline_one.py "$STAGING/$n" "$OUTDIR/$n.json" "$TIER" > "$OUTDIR/logs/$n.log" 2>&1; }
export -f run_one
tail -n +2 "$MANIFEST" | cut -d, -f1 | xargs -P "$PAR" -I {} bash -c 'run_one "$@"' _ {}
echo DONE
