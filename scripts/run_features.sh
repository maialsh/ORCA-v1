#!/usr/bin/env bash
set -u
FR=/Users/maitha/Desktop/Manuscript2_ORCA/ORCA/dry_runs/full_run
PY=/Users/maitha/.local/share/virtualenvs/ORCA-w1m1Q-95/bin/python
export FR PY
mkdir -p "$FR/features325" "$FR/features325/logs"
run_one(){ local n="$1"; [ -f "$FR/features325/$n.json" ] && return 0
  "$PY" "$FR/extract_features_one.py" "$FR/staging/$n" "$FR/features325/$n.json" > "$FR/features325/logs/$n.log" 2>&1; }
export -f run_one
tail -n +2 "$1" | cut -d, -f1 | xargs -P 4 -I {} bash -c 'run_one "$@"' _ {}
echo DONE
