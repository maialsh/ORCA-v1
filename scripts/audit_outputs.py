"""Audit an ORCA output directory for junk verdicts (LLM failures, quota death).

Usage: audit_outputs.py <outdir> [--quarantine]

A valid output has malware_analysis.assessment.classification in
{benign, suspicious, malicious}. Anything else (missing, "unknown", error text)
is junk — typically written after API-quota exhaustion — and blocks resume,
because run_parallel.sh skips any existing .json. With --quarantine, junk files
move to <outdir>/quarantine_quota/ so a resumed run redoes them.
"""
import json, glob, os, shutil, sys

outdir = sys.argv[1]
quarantine = "--quarantine" in sys.argv
VALID = ("benign", "suspicious", "malicious")

junk, ok = [], 0
for f in sorted(glob.glob(os.path.join(outdir, "*.json"))):
    try:
        d = json.load(open(f))
        cls = ((d.get("malware_analysis") or {}).get("assessment") or {}).get("classification")
    except Exception:
        cls = None
    if cls in VALID:
        ok += 1
    else:
        junk.append((f, cls))

print(f"{outdir}: {ok} valid, {len(junk)} junk")
for f, cls in junk:
    print(f"  {os.path.basename(f)}  classification={cls!r}")
if junk and quarantine:
    qdir = os.path.join(outdir, "quarantine_quota")
    os.makedirs(qdir, exist_ok=True)
    for f, _ in junk:
        shutil.move(f, os.path.join(qdir, os.path.basename(f)))
    print(f"quarantined {len(junk)} -> {qdir}")
sys.exit(1 if junk else 0)
