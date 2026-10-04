"""
ORCA Meta-Orchestrator

Composes the binary and malware analysis sub-graphs into a plan based on the
analysis goal. Produces a unified OrcaReport.
"""
from __future__ import annotations
import json
from typing import Any, Dict, List, Optional
from langgraph.graph import StateGraph, END
from langchain_core.messages import AIMessage, HumanMessage

from orca.core.state import OrcaWorkflowState
from orca.core.llm.provider import LLMProvider

llm = LLMProvider()


# ── Planning Agent ─────────────────────────────────────────────

def planning_agent(state: OrcaWorkflowState) -> Dict:
    """Build a dynamic execution plan based on inputs and goal."""
    goal = (state.get("goal") or "comprehensive").lower()
    has_binary = bool(state.get("binary_path"))
    plan: List[str] = []

    # Binary domain steps
    if has_binary:
        plan.append("static_analysis")
        # Deep analysis agents (cross-refs, string threat, string cross-refs)
        plan.extend(["api_crossrefs", "string_threat_analysis", "string_crossref_analysis"])
        if "capabilities" in goal or "comprehensive" in goal:
            plan.extend(["api_clustering", "capabilities_analysis"])
        if "malware" in goal or "triage" in goal or "comprehensive" in goal:
            plan.extend(["triage", "ioc_extraction", "mitre_mapping", "malware_assessment"])
        plan.append("binary_summary")

    # Final summary always
    plan.append("final_summary")

    # Component ablation (experiments only): ORCA_ABLATE is a comma-separated
    # list of step names to remove from the plan. Downstream agents read the
    # missing products via .get() defaults, so the evidence degrades without
    # any other code path changing.
    import os
    ablate = {s.strip() for s in os.environ.get("ORCA_ABLATE", "").split(",") if s.strip()}
    ablated = sorted(ablate & set(plan))
    if ablated:
        plan = [s for s in plan if s not in ablate]

    msg = f"Plan created ({len(plan)} steps): {', '.join(plan)}"
    if ablated:
        msg += f" [ABLATED: {', '.join(ablated)}]"

    return {
        "plan": plan,
        "current_step": 0,
        "completed_steps": [],
        "ablated_steps": ablated,
        "messages": [AIMessage(content=msg)],
    }


# ── Final Summary Agent ───────────────────────────────────────

def final_summary_agent(state: OrcaWorkflowState) -> Dict:
    """Generate executive summary consolidating all domains."""
    data = {
        "binary_domain": state.get("binary_domain", {}),
        "malware_domain": state.get("malware_domain", {}),
        "goal": state.get("goal", ""),
    }
    try:
        report = llm.query_json(
            system="You are ORCA, a security analysis platform. Generate a final report.",
            user=f"""Generate executive summary covering all analysis domains.
Return JSON: executive_summary, recommendations[], threat_assessment.
Data: {json.dumps(data, default=str)[:5000]}""",
        )
    except Exception as exc:
        report = {"executive_summary": f"Report generation failed: {exc}", "recommendations": []}

    return {
        "final_report": report,
        "analysis_complete": True,
        "current_step": (state.get("current_step") or 0) + 1,
        "completed_steps": (state.get("completed_steps") or []) + ["final_summary"],
        "messages": [AIMessage(content="Analysis complete. Final report generated.")],
    }


# ── Routing ────────────────────────────────────────────────────

def route_next(state: OrcaWorkflowState) -> str:
    plan = state.get("plan") or []
    step = state.get("current_step") or 0
    if step >= len(plan):
        return END
    return plan[step]


# ── Agent imports (lazy) ───────────────────────────────────────

def _get_agent_map():
    from orca.domains.binary.workflow import (
        static_analysis_agent, api_crossref_agent,
        string_threat_agent, string_crossref_agent,
        api_clustering_agent,
        capabilities_agent, binary_summary_agent,
    )
    from orca.domains.malware.workflow import (
        triage_agent, ioc_extraction_agent,
        mitre_mapping_agent, malware_assessment_agent,
    )
    return {
        "static_analysis": static_analysis_agent,
        "api_crossrefs": api_crossref_agent,
        "string_threat_analysis": string_threat_agent,
        "string_crossref_analysis": string_crossref_agent,
        "api_clustering": api_clustering_agent,
        "capabilities_analysis": capabilities_agent,
        "binary_summary": binary_summary_agent,
        "triage": triage_agent,
        "ioc_extraction": ioc_extraction_agent,
        "mitre_mapping": mitre_mapping_agent,
        "malware_assessment": malware_assessment_agent,
    }


# ── Graph Builder ──────────────────────────────────────────────

def create_orca_workflow() -> StateGraph:
    agent_map = _get_agent_map()

    g = StateGraph(OrcaWorkflowState)

    # Add all agent nodes
    g.add_node("planning", planning_agent)
    for name, fn in agent_map.items():
        g.add_node(name, fn)
    g.add_node("final_summary", final_summary_agent)

    g.set_entry_point("planning")

    # Build routing targets
    targets = {name: name for name in agent_map}
    targets["final_summary"] = "final_summary"
    targets[END] = END

    # Planning routes to first step
    g.add_conditional_edges("planning", route_next, targets)

    # Each agent routes to next step
    for name in list(agent_map.keys()) + ["final_summary"]:
        g.add_conditional_edges(name, route_next, targets)

    return g


def run_orca(
    *,
    binary_path: Optional[str] = None,
    functionality: str = "",
    goal: str = "comprehensive",
) -> Dict[str, Any]:
    """Main entry point — run the full ORCA pipeline."""
    workflow = create_orca_workflow()
    app = workflow.compile()

    initial_state: Dict[str, Any] = {
        "binary_path": binary_path,
        "binary_functionality": functionality,
        "goal": goal,
        "user_message": None,
        "messages": [HumanMessage(content=f"Analyse: binary={binary_path}, goal={goal}")],
        "completed_steps": [],
        "binary_domain": {},
        "malware_domain": {},
    }

    return app.invoke(initial_state)
