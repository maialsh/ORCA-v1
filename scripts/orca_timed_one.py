"""Timed ORCA run for one binary (R2#2 / R4#8 instrumentation).

Runs the identical comprehensive CLI pipeline, but wraps every worker agent
and every LLM request with a wall-clock timer. Verdicts from these runs are
NOT used anywhere; only timing, token, and cost metrics are kept.

Usage: orca_timed_one.py <binary_path> <out.json> <timing.json>
"""
import sys, json, time

sys.path.insert(0, "/Users/maitha/Desktop/Manuscript2_ORCA/ORCA")

binary_path, out_path, timing_path = sys.argv[1], sys.argv[2], sys.argv[3]

STEP_TIMES = []   # (step_name, seconds)
LLM_TIMES = []    # seconds per request, aligned with per_request usage order

# -- wrap LLM transport ------------------------------------------------------
from orca.core.llm.provider import LLMProvider
_orig_send = LLMProvider._send

def _timed_send(self, messages, **kw):
    t0 = time.monotonic()
    try:
        return _orig_send(self, messages, **kw)
    finally:
        LLM_TIMES.append(round(time.monotonic() - t0, 3))

LLMProvider._send = _timed_send
LLMProvider.reset_usage()

# -- wrap worker agents ------------------------------------------------------
import orca.domains.binary.workflow as bw
import orca.domains.malware.workflow as mw
import orca.core.orchestrator as oc

def _timed(name, fn):
    def wrapper(state):
        t0 = time.monotonic()
        try:
            return fn(state)
        finally:
            STEP_TIMES.append((name, round(time.monotonic() - t0, 3)))
    return wrapper

for mod, attr in [
    (bw, "static_analysis_agent"), (bw, "api_crossref_agent"),
    (bw, "string_threat_agent"), (bw, "string_crossref_agent"),
    (bw, "api_clustering_agent"), (bw, "capabilities_agent"),
    (bw, "binary_summary_agent"),
    (mw, "triage_agent"), (mw, "ioc_extraction_agent"),
    (mw, "mitre_mapping_agent"), (mw, "malware_assessment_agent"),
    (oc, "final_summary_agent"),
]:
    setattr(mod, attr, _timed(attr, getattr(mod, attr)))

# -- run the standard CLI ----------------------------------------------------
t_total0 = time.monotonic()
import orca.cli
sys.argv = ["orca", "-b", binary_path, "--goal", "comprehensive",
            "-o", out_path, "--format", "json"]
try:
    orca.cli.main()
except SystemExit:
    pass
t_total = time.monotonic() - t_total0

usage = LLMProvider.get_usage()
per_req = LLMProvider.get_usage_per_request()
for i, r in enumerate(per_req):
    r["seconds"] = LLM_TIMES[i] if i < len(LLM_TIMES) else None

json.dump({
    "binary": binary_path.rsplit("/", 1)[-1],
    "total_seconds": round(t_total, 2),
    "step_seconds": STEP_TIMES,
    "llm_seconds_sum": round(sum(LLM_TIMES), 2),
    "llm_requests": len(LLM_TIMES),
    "usage_totals": usage,
    "per_request": per_req,
}, open(timing_path, "w"), indent=2)
print(f"TIMING total={t_total:.1f}s llm_sum={sum(LLM_TIMES):.1f}s requests={len(LLM_TIMES)}")
