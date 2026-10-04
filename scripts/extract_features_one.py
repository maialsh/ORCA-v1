"""Extract classifier features for one binary (R1#1 RF/XGBoost baseline).

Uses ORCA's own static extraction backend (Binary Ninja, no LLM calls, $0)
and persists exactly the artifacts ORCA's agents see, reduced to numbers:
imports (names kept for vectorization), string counts, section entropy,
function statistics, file metadata.

Usage: extract_features_one.py <binary_path> <out.json>
"""
import sys, json
sys.path.insert(0, "/Users/maitha/Desktop/Manuscript2_ORCA/ORCA")
from orca.domains.binary.workflow import static_analysis_agent

binary_path, out_path = sys.argv[1], sys.argv[2]

st = static_analysis_agent({"binary_path": binary_path})
sa = (st.get("binary_domain") or {}).get("static_analysis") or {}
fi = sa.get("file_info", {}) or {}
imports = sa.get("imports", []) or []
strings = (sa.get("strings", {}) or {}).get("raw", []) or []
sections = sa.get("sections", []) or []
functions = sa.get("functions", []) or []

sizes = [f.get("size", 0) or 0 for f in functions]
entropies = [s.get("entropy") for s in sections if isinstance(s.get("entropy"), (int, float))]
str_lens = [len(x) for x in strings]

json.dump({
    "imports": imports,
    "features": {
        "size": fi.get("size", 0),
        "is_stripped": int(bool(fi.get("is_stripped"))),
        "is_packed": int(bool(fi.get("is_packed"))),
        "has_cpp_symbols": int(bool(fi.get("has_cpp_symbols"))),
        "format_pe": int(fi.get("binary_format") == "PE"),
        "format_elf": int(fi.get("binary_format") == "ELF"),
        "imports_count": len(imports),
        "strings_count": len(strings),
        "strings_avg_len": (sum(str_lens) / len(str_lens)) if str_lens else 0,
        "sections_count": len(sections),
        "entropy_max": max(entropies) if entropies else 0,
        "entropy_mean": (sum(entropies) / len(entropies)) if entropies else 0,
        "high_entropy_sections": sum(1 for e in (entropies or []) if e > 7.0),
        "functions_count": sa.get("functions_total_count", 0),
        "function_size_max": max(sizes) if sizes else 0,
        "function_size_mean": (sum(sizes) / len(sizes)) if sizes else 0,
    },
}, open(out_path, "w"), indent=1)
print("OK", out_path)
