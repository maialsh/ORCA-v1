"""Verdict agreement across repeated identical runs (R5#12 stability check).

Usage: stability_agreement.py <manifest.csv> <outdir1> <outdir2> [outdir3 ...]

Reports per-binary verdict tuples, three-tier and flag-level agreement rates,
and confidence spread across runs.
"""
import csv, json, os, sys, itertools

manifest, outdirs = sys.argv[1], sys.argv[2:]
rows = list(csv.DictReader(open(manifest)))


def verdict(outdir, name):
    jp = os.path.join(outdir, name + ".json")
    if not os.path.exists(jp):
        return None, None
    a = (json.load(open(jp)).get("malware_analysis") or {}).get("assessment") or {}
    return a.get("classification"), a.get("confidence")


flag = lambda c: c in ("malicious", "suspicious")

full_agree = flag_agree = n = 0
pair_same, pair_total = 0, 0
disagreements = []
for r in rows:
    name = r["neutral_name"]
    vs = [verdict(d, name) for d in outdirs]
    if any(v[0] is None for v in vs):
        print(f"MISSING: {name} in some run, skipped")
        continue
    n += 1
    cls = [v[0] for v in vs]
    confs = [v[1] for v in vs]
    if len(set(cls)) == 1:
        full_agree += 1
    if len(set(flag(c) for c in cls)) == 1:
        flag_agree += 1
    for a, b in itertools.combinations(cls, 2):
        pair_total += 1
        pair_same += a == b
    if len(set(cls)) > 1 or len(set(confs)) > 1:
        disagreements.append((name, r["truth"], r.get("family", ""), cls, confs))

print(f"n={n} binaries x {len(outdirs)} runs")
print(f"identical three-tier verdict in all runs: {full_agree}/{n}")
print(f"identical flag (malicious|suspicious vs benign) in all runs: {flag_agree}/{n}")
print(f"pairwise three-tier agreement: {pair_same}/{pair_total} ({pair_same/pair_total*100:.1f}%)")
print("\nAny verdict or confidence variation:")
for name, truth, fam, cls, confs in disagreements:
    print(f"  {name} ({truth}/{fam}): verdicts {cls} confidences {confs}")
if not disagreements:
    print("  none — all runs identical including confidences")
