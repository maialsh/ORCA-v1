#!/usr/bin/env bash
# Process-parallel runner: one ISOLATED CLI process per binary (Binary Ninja is
# not thread-safe, so we use process isolation, not the thread-based batch).
# Usage: run_parallel.sh <staging_dir> <manifest.csv> <out_dir> [parallel]
set -u
STAGING="$1"; MANIFEST="$2"; OUTDIR="$3"; PAR="${4:-8}"
export PY="${PY:-python3}"
export STAGING OUTDIR
mkdir -p "$OUTDIR" "$OUTDIR/logs"
cd "$(dirname "$0")/.."   # repository root

run_one() {
  local n="$1"
  [ -f "$OUTDIR/$n.json" ] && return 0   # resume: skip done
  "$PY" -m orca.cli -b "$STAGING/$n" --goal comprehensive -o "$OUTDIR/$n.json" --format json > "$OUTDIR/logs/$n.log" 2>&1
}
export -f run_one

t0=$(date +%s)
tail -n +2 "$MANIFEST" | cut -d, -f1 | xargs -P "$PAR" -I {} bash -c 'run_one "$@"' _ {}
t1=$(date +%s)
echo "DONE in $((t1-t0))s ($(( (t1-t0)/60 )) min), parallel=$PAR"
