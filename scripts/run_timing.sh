#!/usr/bin/env bash
set -u
FR=/Users/maitha/Desktop/Manuscript2_ORCA/ORCA/dry_runs/full_run
PY=/Users/maitha/.local/share/virtualenvs/ORCA-w1m1Q-95/bin/python
export FR PY
run_one(){ local n="$1"; [ -f "$FR/outputs_timing/$n.timing.json" ] && return 0
  "$PY" "$FR/orca_timed_one.py" "$FR/staging/$n" "$FR/outputs_timing/$n.json" "$FR/outputs_timing/$n.timing.json" > "$FR/outputs_timing/$n.log" 2>&1; }
export -f run_one
tail -n +2 "$FR/manifest_timing15.csv" | cut -d, -f1 | xargs -P 2 -I {} bash -c 'run_one "$@"' _ {}
echo DONE
