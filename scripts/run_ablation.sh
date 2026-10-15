#!/usr/bin/env bash
# Component-ablation runner: wraps run_parallel.sh with ORCA_ABLATE set,
# so each condition runs the identical pipeline minus the named plan steps.
# Usage: run_ablation.sh <condition> <manifest.csv> <out_dir> [parallel]
# The staged binaries are read from $STAGING (default: ./staging).
# Conditions:
#   noxref    — remove cross-reference analysis (api_crossrefs + string_crossref_analysis)
#   nostrings — remove string analysis (string_threat_analysis + string_crossref_analysis)
#   nocluster — remove API clustering (api_clustering)
set -eu
COND="$1"; MANIFEST="$2"; OUTDIR="$3"; PAR="${4:-6}"
# run_parallel.sh cd's into the ORCA root, so relative paths silently match nothing
MANIFEST="$(cd "$(dirname "$MANIFEST")" && pwd)/$(basename "$MANIFEST")"
mkdir -p "$OUTDIR"
OUTDIR="$(cd "$OUTDIR" && pwd)"
[ -f "$MANIFEST" ] || { echo "manifest not found: $MANIFEST" >&2; exit 1; }
case "$COND" in
  noxref)    ABL="api_crossrefs,string_crossref_analysis" ;;
  nostrings) ABL="string_threat_analysis,string_crossref_analysis" ;;
  nocluster) ABL="api_clustering" ;;
  *) echo "unknown condition: $COND (want noxref|nostrings|nocluster)" >&2; exit 1 ;;
esac
export ORCA_ABLATE="$ABL"
DIR="$(cd "$(dirname "$0")" && pwd)"
# Preflight: verify the API can actually serve a completion before spawning
# workers. A dead account (quota exhausted) otherwise burns hours writing junk
# "unknown" verdicts that block resume.
PF=$(curl -sS -m 30 https://api.openai.com/v1/chat/completions \
  -H "Authorization: Bearer ${OPENAI_API_KEY:?OPENAI_API_KEY not set}" \
  -H "Content-Type: application/json" \
  -d '{"model":"gpt-4o","max_tokens":1,"messages":[{"role":"user","content":"ping"}]}' \
  -o /dev/null -w "%{http_code}")
[ "$PF" = "200" ] || { echo "PREFLIGHT FAILED: chat completion returned HTTP $PF (check credits/key) — aborting before any spend" >&2; exit 2; }
echo "condition=$COND ORCA_ABLATE=$ORCA_ABLATE outdir=$OUTDIR parallel=$PAR"
STAGING="$(cd "${STAGING:-staging}" && pwd)"
exec bash "$DIR/run_parallel.sh" "$STAGING" "$MANIFEST" "$OUTDIR" "$PAR"
