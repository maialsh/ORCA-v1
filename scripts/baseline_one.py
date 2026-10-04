"""Single-prompt baseline for the RQ3 orchestration ablation.

Extracts the SAME raw static artifacts ORCA's tool-based agents see (imports,
strings, decompiled top functions, file metadata) and feeds them to ONE GPT-4o
prompt for a verdict -- no multi-agent decomposition, no shared state, no
per-stage reasoning. This isolates the contribution of the orchestration.

Usage: baseline_one.py <binary_path> <out.json> [tier]
  tier1 (default): all raw artifacts, verdict + reasoning
  tier3          : minimal (imports + strings only)
"""
import sys, json
sys.path.insert(0, "/Users/maitha/Desktop/Manuscript2_ORCA/ORCA")
from orca.domains.binary.workflow import static_analysis_agent
from orca.core.llm.provider import LLMProvider

binary_path, out_path = sys.argv[1], sys.argv[2]
tier = sys.argv[3] if len(sys.argv) > 3 else "tier1"
llm = LLMProvider()

# Extract raw artifacts (reuse ORCA's backend extraction; same inputs the agents get)
st = static_analysis_agent({"binary_path": binary_path})
sa = (st.get("binary_domain") or {}).get("static_analysis") or {}
fi = sa.get("file_info", {})
imports = sa.get("imports", []) or []
strings = (sa.get("strings", {}) or {}).get("raw", []) or []
enriched = sa.get("enriched_functions", []) or []

if tier == "tier3":
    evidence = {
        "file_info": {k: fi.get(k) for k in ("binary_format", "architecture", "is_stripped", "size")},
        "imports": imports[:120],
        "strings_sample": strings[:80],
    }
else:  # tier1 — all raw artifacts ORCA's agents collectively see
    evidence = {
        "file_info": {k: fi.get(k) for k in ("binary_format", "architecture", "is_stripped", "is_packed", "size")},
        "imports_count": len(imports),
        "imports": imports[:120],
        "strings_sample": strings[:100],
        "functions_total": sa.get("functions_total_count", 0),
        "decompiled_top_functions": [
            {"name": f.get("name"), "code": (f.get("decompiled_code") or "")[:900]}
            for f in enriched[:14] if f.get("decompiled_code")
        ],
    }

user = (
    "Classify this binary as exactly one of: benign, suspicious, or malicious, "
    "based only on the static analysis artifacts below.\n\n"
    f"{json.dumps(evidence, indent=2)[:14000]}\n\n"
    'Return JSON: {"classification": "benign|suspicious|malicious", '
    '"reasoning": "<2-3 sentences>"}'
)
try:
    res = llm.query_json(
        system="You are a senior malware analyst. Classify a binary from its static artifacts.",
        user=user,
    )
except Exception as exc:
    res = {"classification": "unknown", "error": str(exc)}

json.dump({"baseline_tier": tier, "assessment": res,
           "imports_count": len(imports), "functions_count": sa.get("functions_total_count", 0)},
          open(out_path, "w"), indent=2)
