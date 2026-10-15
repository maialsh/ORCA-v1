"""Tests for ORCA domain-specific components."""
import json
import pytest


# ── HITL Manager ───────────────────────────────────────────────

class TestHITL:
    def test_should_not_interrupt_empty(self):
        from orca.core.hitl import HITLManager
        hitl = HITLManager()
        assert not hitl.should_interrupt({"completed_steps": []})

    def test_should_interrupt_after_assessment(self):
        from orca.core.hitl import HITLManager
        hitl = HITLManager(interrupt_after={"malware_assessment"})
        state = {"completed_steps": ["static_analysis", "malware_assessment"]}
        assert hitl.should_interrupt(state)

    def test_auto_approve_low_risk(self):
        from orca.core.hitl import HITLManager
        hitl = HITLManager(
            interrupt_after={"malware_assessment"},
            auto_approve_low_risk=True,
            risk_threshold=50,
        )
        state = {
            "completed_steps": ["malware_assessment"],
            "malware_domain": {"mitre": {"threat_score": 20}},
        }
        assert not hitl.should_interrupt(state)

    def test_submit_review(self):
        from orca.core.hitl import HITLManager
        hitl = HITLManager()
        state = {
            "_hitl_waiting": True,
            "malware_domain": {"analysis": {"classification": "unknown"}},
            "messages": [],
        }
        state = hitl.submit_review(
            state, approved=True,
            override_classification="trojan",
            notes="Confirmed by analyst",
        )
        assert not state["_hitl_waiting"]
        assert state["malware_domain"]["analysis"]["classification"] == "trojan"
        assert state["malware_domain"]["analysis"]["analyst_override"] is True


# ── Reporting Engine ───────────────────────────────────────────

class TestReporting:
    def test_json_report(self):
        from orca.core.reporting.engine import ReportEngine
        engine = ReportEngine({"completed_steps": ["static_analysis"], "binary_domain": {}})
        text = engine.to_json()
        data = json.loads(text)
        assert "orca_version" in data
        assert "timestamp" in data

    def test_html_report(self):
        from orca.core.reporting.engine import ReportEngine
        engine = ReportEngine({"completed_steps": ["triage"], "malware_domain": {"triage": {"entropy_score": 5.5}}})
        html = engine.to_html()
        assert "<!DOCTYPE html>" in html
        assert "ORCA Analysis Report" in html

    def test_sarif_report(self):
        from orca.core.reporting.engine import ReportEngine
        engine = ReportEngine({
            "malware_domain": {
                "mitre": {"techniques": [{"technique_id": "T1055", "name": "Process Injection", "severity": "high"}]},
                "iocs": [{"ioc_type": "ip", "value": "1.2.3.4", "confidence": 0.9}],
            },
        })
        text = engine.to_sarif()
        data = json.loads(text)
        assert data["version"] == "2.1.0"
        assert len(data["runs"][0]["results"]) >= 2
