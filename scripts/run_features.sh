#!/usr/bin/env bash
# Extract classifier features for every binary in a manifest.
# Usage: run_features.sh <staging_dir> <manifest.csv> <out_dir> [parallel]
set -u
STAGING="$(cd "$1" && pwd)"; MANIFEST="$2"; OUTDIR="$3"; PAR="${4:-4}"
mkdir -p "$OUTDIR/logs"; OUTDIR="$(cd "$OUTDIR" && pwd)"
export PY="${PY:-python3}" SCRIPTS="$(cd "$(dirname "$0")" && pwd)" STAGING OUTDIR
run_one(){ local n="$1"; [ -f "$OUTDIR/$n.json" ] && return 0
  "$PY" "$SCRIPTS/extract_features_one.py" "$STAGING/$n" "$OUTDIR/$n.json" > "$OUTDIR/logs/$n.log" 2>&1; }
export -f run_one
tail -n +2 "$MANIFEST" | cut -d, -f1 | xargs -P "$PAR" -I {} bash -c 'run_one "$@"' _ {}
echo DONE
