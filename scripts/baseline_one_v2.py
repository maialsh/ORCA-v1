"""Instrumented single-prompt baseline for the full detection collection.

Identical evidence assembly to baseline_one.py (tier1), plus per-sample
metrics: extraction/LLM latency, input+output tokens, cost, and exact
truncation accounting (what was available vs what fit in the prompt).
Writes one JSON per binary.

Usage: baseline_one_v2.py <binary_path> <out.json>
"""
import sys, json, time
sys.path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parents[1]))  # repository root
from orca.domains.binary.workflow import static_analysis_agent
from orca.core.llm.provider import LLMProvider

binary_path, out_path = sys.argv[1], sys.argv[2]
llm = LLMProvider()

t0 = time.monotonic()
st = static_analysis_agent({"binary_path": binary_path})
t_extract = time.monotonic() - t0

sa = (st.get("binary_domain") or {}).get("static_analysis") or {}
fi = sa.get("file_info", {})
imports = sa.get("imports", []) or []
strings = (sa.get("strings", {}) or {}).get("raw", []) or []
enriched = sa.get("enriched_functions", []) or []

# tier1 evidence — byte-for-byte the same construction as baseline_one.py
decomp = [
    {"name": f.get("name"), "code": (f.get("decompiled_code") or "")[:900]}
    for f in enriched[:14] if f.get("decompiled_code")
]
evidence = {
    "file_info": {k: fi.get(k) for k in ("binary_format", "architecture", "is_stripped", "is_packed", "size")},
    "imports_count": len(imports),
    "imports": imports[:120],
    "strings_sample": strings[:100],
    "functions_total": sa.get("functions_total_count", 0),
    "decompiled_top_functions": decomp,
}

evidence_json = json.dumps(evidence, indent=2)
user = (
    "Classify this binary as exactly one of: benign, suspicious, or malicious, "
    "based only on the static analysis artifacts below.\n\n"
    f"{evidence_json[:14000]}\n\n"
    'Return JSON: {"classification": "benign|suspicious|malicious", '
    '"reasoning": "<2-3 sentences>"}'
)

# truncation accounting — what existed vs what the prompt kept
code_chars_available = sum(len(f.get("decompiled_code") or "") for f in enriched)
code_chars_included = sum(len(d["code"]) for d in decomp)
truncation = {
    "imports_available": len(imports),
    "imports_included": min(len(imports), 120),
    "strings_available": len(strings),
    "strings_included": min(len(strings), 100),
    "functions_total": sa.get("functions_total_count", 0),
    "functions_enriched_available": len(enriched),
    "functions_in_prompt": len(decomp),
    "decompiled_chars_available": code_chars_available,
    "decompiled_chars_included": code_chars_included,
    "evidence_chars_before_cap": len(evidence_json),
    "evidence_chars_after_cap": min(len(evidence_json), 14000),
    "evidence_capped": len(evidence_json) > 14000,
}

LLMProvider.reset_usage()
t1 = time.monotonic()
try:
    res = llm.query_json(
        system="You are a senior malware analyst. Classify a binary from its static artifacts.",
        user=user,
    )
except Exception as exc:
    res = {"classification": "unknown", "error": str(exc)}
t_llm = time.monotonic() - t1
usage = LLMProvider.get_usage()

json.dump({
    "baseline_tier": "tier1",
    "assessment": res,
    "imports_count": len(imports),
    "functions_count": sa.get("functions_total_count", 0),
    "metrics": {
        "extract_seconds": round(t_extract, 2),
        "llm_seconds": round(t_llm, 2),
        "total_seconds": round(t_extract + t_llm, 2),
        "input_tokens": usage.get("total_input_tokens"),
        "output_tokens": usage.get("total_output_tokens"),
        "cost_usd": usage.get("total_cost_usd"),
        "requests": usage.get("total_requests"),
        "truncation": truncation,
    },
}, open(out_path, "w"), indent=2)
