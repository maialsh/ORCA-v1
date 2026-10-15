"""Random Forest and XGBoost on ORCA's static features under three splits.

source:  malware family held out, benign programs grouped by source collection
         (Linux utilities, Sysinternals, portable tools), one group per fold
family:  malware family held out, benign programs assigned at random to the folds
standard: stratified five-fold
Usage: rf_xgb_eval_three_splits.py <manifest.csv> <features_dir> [seed]
"""
import csv, json, os, sys
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.model_selection import LeaveOneGroupOut, StratifiedKFold
from xgboost import XGBClassifier

manifest, fdir = sys.argv[1], sys.argv[2]
SEED = int(sys.argv[3]) if len(sys.argv) > 3 else 42
NORM = {"Miner": "Coinminer", "Rootkits": "Rootkit"}

rows = [(r, json.load(open(os.path.join(fdir, r["neutral_name"] + ".json"))))
        for r in csv.DictReader(open(manifest))]
KEYS = sorted(rows[0][1]["features"].keys())
y = np.array([r["truth"] == "malicious" for r, _ in rows], dtype=int)
num = np.array([[d["features"][k] for k in KEYS] for _, d in rows], dtype=float)
docs = [" ".join(d["imports"]) for _, d in rows]
fam = [NORM.get(r["family"], r["family"]) for r, _ in rows]
mal_fams = sorted({f for (r, _), f in zip(rows, fam) if r["truth"] == "malicious"})
rng = np.random.RandomState(SEED)

splits = {
    "source": LeaveOneGroupOut().split(num, y, np.array(fam)),
    "family": LeaveOneGroupOut().split(num, y, np.array(
        [f if r["truth"] == "malicious" else mal_fams[rng.randint(len(mal_fams))]
         for (r, _), f in zip(rows, fam)])),
    "standard": StratifiedKFold(5, shuffle=True, random_state=SEED).split(num, y),
}
models = {"RF": lambda: RandomForestClassifier(n_estimators=300, random_state=42, n_jobs=-1),
          "XGB": lambda: XGBClassifier(n_estimators=300, max_depth=6, random_state=42,
                                       eval_metric="logloss", verbosity=0)}
print(f"n={len(y)} malware={y.sum()} benign={len(y)-y.sum()} seed={SEED}")
for sname, gen in splits.items():
    folds = list(gen)
    for mname, mk in models.items():
        pred = np.zeros(len(y), int)
        for tr, te in folds:
            v = CountVectorizer(max_features=200, binary=True, token_pattern=r"[^ ]+")
            Xtr = np.hstack([num[tr], v.fit_transform([docs[i] for i in tr]).toarray()])
            Xte = np.hstack([num[te], v.transform([docs[i] for i in te]).toarray()])
            m = mk(); m.fit(Xtr, y[tr]); pred[te] = m.predict(Xte)
        TP = int(((pred == 1) & (y == 1)).sum()); FN = int(((pred == 0) & (y == 1)).sum())
        TN = int(((pred == 0) & (y == 0)).sum()); FP = int(((pred == 1) & (y == 0)).sum())
        globals().setdefault("P", {})[(sname, mname)] = pred.copy()
        print(f"{sname:8s} {mname:3s} acc={100*(TP+TN)/len(y):.1f} rec={100*TP/(TP+FN):.1f} "
              f"spec={100*TN/(TN+FP):.1f} F1={2*TP/(2*TP+FP+FN):.2f} TN={TN} FP={FP} folds={len(folds)}")
for s in splits:
    print(f"{s}: RF and XGB agree on {int((P[(s, 'RF')] == P[(s, 'XGB')]).sum())} of {len(y)}")
