"""R1#1: RF/XGBoost baseline on ORCA's static artifacts, family-aware grouped CV.

Groups: malware family for malicious samples, source collection for benign
(benign-Linux, sysinternals, portable-tools). Leave-one-group-out: every
sample is predicted exactly once, by a model that saw no sample of its group.
Import-name vocabulary is fitted inside each training fold only (no leakage).

Usage: rf_xgb_eval.py <manifest.csv> <features_dir> <out.json>
"""
import sys, json, csv, os, time
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.model_selection import LeaveOneGroupOut
from xgboost import XGBClassifier

manifest, fdir, out_path = sys.argv[1], sys.argv[2], sys.argv[3]

rows, skipped = [], []
for r in csv.DictReader(open(manifest)):
    p = os.path.join(fdir, r["neutral_name"] + ".json")
    if not os.path.exists(p):
        skipped.append(r["neutral_name"]); continue
    d = json.load(open(p))
    rows.append((r, d))
print(f"samples: {len(rows)}, missing features: {len(skipped)}")

NUM_KEYS = sorted(rows[0][1]["features"].keys())
y = np.array([1 if r["truth"] == "malicious" else 0 for r, _ in rows])
groups = np.array([r["family"] for r, _ in rows])
num = np.array([[d["features"][k] for k in NUM_KEYS] for _, d in rows], dtype=float)
imp_docs = [" ".join(d["imports"]) for _, d in rows]

def run_model(name, mk):
    logo = LeaveOneGroupOut()
    pred = np.zeros(len(y), dtype=int)
    t_train = t_pred = 0.0
    for tr, te in logo.split(num, y, groups):
        vec = CountVectorizer(max_features=200, binary=True,
                              token_pattern=r"[^ ]+", lowercase=True)
        Xtr = np.hstack([num[tr], vec.fit_transform([imp_docs[i] for i in tr]).toarray()])
        Xte = np.hstack([num[te], vec.transform([imp_docs[i] for i in te]).toarray()])
        m = mk()
        t0 = time.monotonic(); m.fit(Xtr, y[tr]); t_train += time.monotonic() - t0
        t0 = time.monotonic(); pred[te] = m.predict(Xte); t_pred += time.monotonic() - t0
    TP = int(((pred == 1) & (y == 1)).sum()); FN = int(((pred == 0) & (y == 1)).sum())
    TN = int(((pred == 0) & (y == 0)).sum()); FP = int(((pred == 1) & (y == 0)).sum())
    res = dict(model=name, TP=TP, FN=FN, TN=TN, FP=FP,
               accuracy=round((TP + TN) / len(y), 4),
               recall=round(TP / (TP + FN), 4) if TP + FN else None,
               specificity=round(TN / (TN + FP), 4) if TN + FP else None,
               precision=round(TP / (TP + FP), 4) if TP + FP else None,
               f1=round(2 * TP / (2 * TP + FP + FN), 4) if TP else 0.0,
               train_seconds_total=round(t_train, 2), predict_seconds_total=round(t_pred, 2),
               folds=int(logo.get_n_splits(groups=groups)))
    res["predictions"] = {rows[i][0]["neutral_name"]: int(pred[i]) for i in range(len(rows))}
    return res

out = {"n": len(rows), "groups": sorted(set(groups.tolist())), "num_features": NUM_KEYS,
       "skipped": skipped, "results": []}
for name, mk in [
    ("RandomForest", lambda: RandomForestClassifier(n_estimators=300, random_state=42, n_jobs=-1)),
    ("XGBoost", lambda: XGBClassifier(n_estimators=300, max_depth=6, random_state=42,
                                      eval_metric="logloss", n_jobs=-1, verbosity=0)),
]:
    r = run_model(name, mk)
    out["results"].append(r)
    print(f"{name}: acc={r['accuracy']:.1%} rec={r['recall']:.1%} spec={r['specificity']:.1%} "
          f"F1={r['f1']:.2f} train={r['train_seconds_total']}s predict={r['predict_seconds_total']}s")
json.dump(out, open(out_path, "w"), indent=1)
