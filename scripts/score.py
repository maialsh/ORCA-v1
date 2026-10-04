"""Score per-binary ORCA JSON outputs against a truth manifest.
Usage: score.py <manifest.csv> <out_dir>
Treats 'malicious' or 'suspicious' as a positive (flagged) verdict for recall.
"""
import sys, csv, json, os

manifest, outdir = sys.argv[1], sys.argv[2]
rows = list(csv.DictReader(open(manifest)))


def label(r):
    return r.get("private_label") or r.get("family") or ""


with open(os.path.join(outdir, "scored.csv"), "w", newline="") as f:
    w = csv.writer(f)
    w.writerow(["neutral", "label", "platform", "truth", "classification", "confidence", "rule", "low_cov"])
    results = []
    for r in rows:
        n = r["neutral_name"]
        jp = os.path.join(outdir, n + ".json")
        if not os.path.exists(jp):
            w.writerow([n, label(r), r.get("platform", ""), r["truth"], "MISSING", "", "", ""])
            continue
        try:
            d = json.load(open(jp))
            a = (d.get("malware_analysis") or {}).get("assessment") or {}
            cov = a.get("analysis_coverage") or {}
            w.writerow([n, label(r), r.get("platform", ""), r["truth"], a.get("classification", ""),
                        a.get("confidence", ""), a.get("decision_rule_fired", ""), cov.get("low_coverage", "")])
            results.append((r["truth"], a.get("classification", "")))
        except Exception as e:
            w.writerow([n, label(r), r.get("platform", ""), r["truth"], f"ERR:{e}", "", "", ""])

flag = lambda c: c in ("malicious", "suspicious")
TP = sum(1 for t, c in results if t == "malicious" and flag(c))
FN = sum(1 for t, c in results if t == "malicious" and not flag(c))
TN = sum(1 for t, c in results if t == "benign" and not flag(c))
FP = sum(1 for t, c in results if t == "benign" and flag(c))
mal = sum(1 for t, c in results if t == "malicious")
ben = sum(1 for t, c in results if t == "benign")
print(f"scored {len(results)} binaries ({mal} malicious, {ben} benign)")
print(f"  flagged(malicious|suspicious) as positive: TP={TP} FN={FN} TN={TN} FP={FP}")
if TP + FN:
    print(f"  recall={TP/(TP+FN):.3f}")
if TP + FP:
    print(f"  precision={TP/(TP+FP):.3f}")
mTP = sum(1 for t, c in results if t == "malicious" and c == "malicious")
mFP = sum(1 for t, c in results if t == "benign" and c == "malicious")
print(f"  malicious-only verdict: malware->malicious {mTP}/{mal}, benign->malicious(FP) {mFP}/{ben}")
