#!/usr/bin/env bash
# Timed ORCA runs for every binary in a manifest.
# Usage: run_timing.sh <staging_dir> <manifest.csv> <out_dir> [parallel]
set -u
STAGING="$(cd "$1" && pwd)"; MANIFEST="$2"; OUTDIR="$3"; PAR="${4:-2}"
mkdir -p "$OUTDIR"; OUTDIR="$(cd "$OUTDIR" && pwd)"
export PY="${PY:-python3}" SCRIPTS="$(cd "$(dirname "$0")" && pwd)" STAGING OUTDIR
run_one(){ local n="$1"; [ -f "$OUTDIR/$n.timing.json" ] && return 0
  "$PY" "$SCRIPTS/orca_timed_one.py" "$STAGING/$n" "$OUTDIR/$n.json" "$OUTDIR/$n.timing.json" > "$OUTDIR/$n.log" 2>&1; }
export -f run_one
tail -n +2 "$MANIFEST" | cut -d, -f1 | xargs -P "$PAR" -I {} bash -c 'run_one "$@"' _ {}
echo DONE
