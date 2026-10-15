# ORCA v1

Code and run scripts for the paper:

> **Orchestrated Multi-Agent and LLM-Based Reasoning for Static Binary Code Analysis**
> Maitha Alshaali, Wanqing Tu, Hakim Hacid

This repository is a frozen snapshot of the version of ORCA evaluated in the paper. ORCA analyzes a
compiled Linux or Windows binary with static analysis only. A fixed multi-agent pipeline extracts
artifacts with Binary Ninja (imports, strings, cross-references, API clusters, decompiled code), and
language-model agents correlate them into a capability description and a verdict of benign,
suspicious, or malicious, with the supporting evidence.

Later versions of ORCA are developed separately and are not part of this snapshot.

## Contents

| Path | What |
|---|---|
| `orca/` | The ORCA pipeline used in the paper. The triage workflow is in `orca/domains/malware/` and `orca/domains/binary/`, orchestration in `orca/core/`. |
| `scripts/` | The scripts used to run the experiments: batch runs, the single-prompt baseline, component ablations, timing, the Random Forest and XGBoost comparison, scoring and stability agreement. |
| `data/` | The manifest of the 306 binaries in the detection collection, with hashes, labels, families, sources, names, and the selection rules (see `data/README.md`). |

No binaries are included. ORCA uses static analysis only; never execute malware samples.

## Running ORCA

Requirements: Python 3, the packages in `Pipfile`, a Binary Ninja licence with its Python API, and
either API access to a language model or a local model served through Ollama.

```
pipenv install
python -m orca.cli --binary /path/to/binary --goal comprehensive -o report.json
```

The experiments used `--goal comprehensive`. The batch scripts in `scripts/` take a folder of staged
binaries, a manifest of samples, and an output folder, and run from the repository root. Set `PY` to
the Python interpreter of the environment if it is not `python3`. Ablation conditions are selected
with the `ORCA_ABLATE` environment variable (comma-separated step names). `scripts/rf_xgb_eval.py`
reproduces the classifier comparison under the family, source, and standard splits. It also needs
`scikit-learn` and `xgboost` (`pip install scikit-learn xgboost`).

## Licence

MIT, see `LICENSE`.
