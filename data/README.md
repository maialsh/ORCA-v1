# Detection dataset manifest

`detection_manifest_304.csv` lists the 304 binaries used for malicious behavior detection
(RQ2, RQ3, RQ4) in the paper: 169 malware samples and 135 benign programs, on Linux and Windows.
No binaries are included. ORCA uses static analysis only; never execute malware samples.

## Columns

| Column | Meaning |
|---|---|
| `sha256` | SHA-256 of the analyzed file. The paper's neutral file names are the first 16 hex characters. |
| `label` | Ground truth, `malicious` or `benign`, from the source of the sample. |
| `platform` | `linux` or `windows`. |
| `format` | `ELF` or `PE` as loaded by Binary Ninja, or `not parsed by Binary Ninja` for the seven malware samples that Binary Ninja could not load as ELF or PE. |
| `family_or_category` | Malware family category as in Table 3 of the paper, or the benign category. |
| `source` | MalwareBazaar for malware; Linux distribution package, Microsoft Sysinternals suite, or portable Windows tool for benign programs. |
| `name` | MalwareBazaar signature for malware where one is assigned; program file name for benign programs. |
| `version` | File version from the PE version information of Windows benign programs where present. The Linux binaries carry no version string. |
| `added_month` | Month in which the file was added to the study collection. Empty where it was not recorded. |

## Features

`features/<sha256>.json` holds, for every binary, the static features used in the Random Forest and
XGBoost comparison: the imported API names and the numeric features (file size, stripped and packed
flags, format, import and string counts, average string length, section count and entropy, function
count and size). They were extracted with ORCA's Binary Ninja backend by `scripts/extract_features_one.py`.
`scripts/rf_xgb_eval.py` reads them together with the manifest.

## Selection rules

- Malware samples were drawn per family from MalwareBazaar submissions and deduplicated by content
  hash. The malware is stratified across thirteen family categories and includes a group of packed
  samples on both platforms. Family labels follow the MalwareBazaar submitter tags.
- Benign programs are unmodified release builds of widely used software: Linux system and core
  utilities from standard distribution packages, 93 of the 149 executables of the Sysinternals suite,
  and five portable Windows tools. The Sysinternals suite was subsampled so that the benign class
  balances the malware count, not curated by tool.
- Every benign program is a native ELF or PE executable, verified by loading it in Binary Ninja.
- Every file was renamed to a neutral identifier derived from its content hash before analysis, so
  that no model receives a file name.

## Obtaining the samples

Malware samples can be downloaded from MalwareBazaar (https://bazaar.abuse.ch) by their SHA-256.
Benign programs are available from their distribution packages and from Microsoft Sysinternals.
