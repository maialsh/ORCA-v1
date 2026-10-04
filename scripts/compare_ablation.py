"""Compare an ablation run against the reference ORCA run (R4#6).

Usage: compare_ablation.py <manifest.csv> <ref_outdir> <abl_outdir> [flips.csv]

Flag-level scoring (malicious|suspicious = positive), identical to score.py.
Reports per-arm metrics, paired disagreements, and exact McNemar p-value.
"""
import sys, csv, json, os

manifest, refdir, abldir = sys.argv[1], sys.argv[2], sys.argv[3]
flips_out = sys.argv[4] if len(sys.argv) > 4 else None
rows = list(csv.DictReader(open(manifest)))


def verdict(outdir, name):
    jp = os.path.join(outdir, name + ".json")
    if not os.path.exists(jp):
        return None
    try:
        d = json.load(open(jp))
        a = (d.get("malware_analysis") or {}).get("assessment") or {}
        return a.get("classification") or None
    except Exception:
        return None


def flag(c):
    return c in ("malicious", "suspicious")


def metrics(pairs):
    TP = sum(1 for t, c in pairs if t == "malicious" and flag(c))
    FN = sum(1 for t, c in pairs if t == "malicious" and not flag(c))
    TN = sum(1 for t, c in pairs if t == "benign" and not flag(c))
    FP = sum(1 for t, c in pairs if t == "benign" and flag(c))
    n = TP + FN + TN + FP
    acc = (TP + TN) / n if n else 0
    rec = TP / (TP + FN) if TP + FN else 0
    spec = TN / (TN + FP) if TN + FP else 0
    prec = TP / (TP + FP) if TP + FP else 0
    f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0
    return dict(TP=TP, FN=FN, TN=TN, FP=FP, n=n, acc=acc, rec=rec, spec=spec, prec=prec, f1=f1)


paired = []          # (row, ref_verdict, abl_verdict) where both present
missing_ref, missing_abl = [], []
for r in rows:
    n = r["neutral_name"]
    rv, av = verdict(refdir, n), verdict(abldir, n)
    if rv is None:
        missing_ref.append(n)
    if av is None:
        missing_abl.append(n)
    if rv is not None and av is not None:
        paired.append((r, rv, av))

if missing_ref:
    print(f"WARNING: {len(missing_ref)} missing in reference: {missing_ref[:5]}")
if missing_abl:
    print(f"WARNING: {len(missing_abl)} missing in ablation: {missing_abl[:5]}")

ref_m = metrics([(r["truth"], v) for r, v, _ in paired])
abl_m = metrics([(r["truth"], v) for r, _, v in paired])
fmt = lambda m: (f"acc={m['acc']*100:.1f} rec={m['rec']*100:.1f} spec={m['spec']*100:.1f} "
                 f"F1={m['f1']:.2f} (TP={m['TP']} FN={m['FN']} TN={m['TN']} FP={m['FP']}, n={m['n']})")
print(f"reference: {fmt(ref_m)}")
print(f"ablation : {fmt(abl_m)}")

# Paired disagreement at flag level: b = ref correct & abl wrong, c = ref wrong & abl correct
b = c = 0
flips = []
for r, rv, av in paired:
    truth_pos = r["truth"] == "malicious"
    ref_ok = flag(rv) == truth_pos
    abl_ok = flag(av) == truth_pos
    if rv != av:
        flips.append((r["neutral_name"], r["truth"], r.get("platform", ""), r.get("family", ""), rv, av))
    if ref_ok and not abl_ok:
        b += 1
    elif abl_ok and not ref_ok:
        c += 1

print(f"verdict-level flips (any 3-tier change): {len(flips)}")
print(f"flag-level discordant pairs: b(ref right, abl wrong)={b}, c(abl right, ref wrong)={c}")
try:
    from scipy.stats import binomtest
    if b + c:
        p = binomtest(b, b + c, 0.5).pvalue
        print(f"McNemar exact (binomial, two-sided): p={p:.6g}")
    else:
        print("McNemar: no discordant pairs")
except ImportError:
    print("scipy not available — install for McNemar p-value")

if flips_out:
    with open(flips_out, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["neutral", "truth", "platform", "family", "ref_verdict", "abl_verdict"])
        w.writerows(flips)
    print(f"flips written to {flips_out}")
