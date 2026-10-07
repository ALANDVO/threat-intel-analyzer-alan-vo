"""Unit tests for deterministic security briefing generator and markdown export."""
import pytest
from app.models.entities import ScanFindingEntity, ThreatScanEntity
from app.services.briefing_engine import BriefingEngine


def test_briefing_synthesis_and_metrics():
    scan = ThreatScanEntity(
        id="scan-123",
        title="Production Perimeter Scan",
        scanned_assets_count=5,
        findings_count=2,
        critical_count=1,
        high_count=1,
        medium_count=0,
        low_count=0,
        created_by="analyst@test.local"
    )

    finding1 = ScanFindingEntity(
        id="f-1",
        scan_id=scan.id,
        asset_id="a-1",
        vulnerability_id="CVE-2024-3094",
        asset_name="auth-service",
        asset_component="xz-utils",
        asset_version="5.6.0",
        cve_id="CVE-2024-3094",
        cvss_score=10.0,
        epss_score=0.88,
        is_cisa_kev=True,
        asset_criticality="tier_1",
        internet_exposed=True,
        composite_risk_score=95.0,
        priority_tier="CRITICAL",
        match_reason="Matches affected spec",
        score_breakdown={},
        remediation_recommendation="Upgrade to 5.6.1-2"
    )

    finding2 = ScanFindingEntity(
        id="f-2",
        scan_id=scan.id,
        asset_id="a-2",
        vulnerability_id="CVE-2023-44487",
        asset_name="web-edge",
        asset_component="nginx",
        asset_version="1.20.0",
        cve_id="CVE-2023-44487",
        cvss_score=7.5,
        epss_score=0.65,
        is_cisa_kev=True,
        asset_criticality="tier_1",
        internet_exposed=True,
        composite_risk_score=78.0,
        priority_tier="HIGH",
        match_reason="Matches affected spec",
        score_breakdown={},
        remediation_recommendation="Upgrade to 1.25.3"
    )

    briefing = BriefingEngine.generate_briefing(
        title="Q4 Executive Security Briefing",
        target_date="2026-10-07",
        scan=scan,
        findings=[finding1, finding2],
        created_by="analyst@test.local"
    )

    stats = briefing["summary_stats"]
    assert stats["total_findings"] == 2
    assert stats["critical_count"] == 1
    assert stats["high_count"] == 1
    assert stats["cisa_kev_active_count"] == 2
    assert stats["internet_exposed_count"] == 2
    assert stats["average_composite_score"] == 86.5

    assert "ELEVATED RISK POSTURE" in briefing["executive_summary"]
    assert len(briefing["top_threats"]) == 2

    # Playbook validation
    phases = [p["phase"] for p in briefing["mitigation_playbook"]]
    assert "containment" in phases
    assert "remediation" in phases
    assert "verification" in phases


def test_briefing_markdown_rendering():
    briefing_data = {
        "title": "Board Briefing",
        "target_date": "2026-10-07",
        "created_by": "analyst@test.local",
        "summary_stats": {"total_findings": 1, "critical_count": 1, "average_composite_score": 90.0},
        "executive_summary": "Test executive summary narrative.",
        "top_threats": [{
            "priority_tier": "CRITICAL",
            "cve_id": "CVE-2024-3094",
            "asset_name": "prod-ssh",
            "asset_component": "xz-utils",
            "asset_version": "5.6.0",
            "composite_risk_score": 95.0,
            "remediation": "Upgrade immediately"
        }],
        "mitigation_playbook": [{
            "phase": "containment",
            "title": "Isolate Port",
            "target_asset": "prod-ssh",
            "target_cve": "CVE-2024-3094",
            "description": "Block port 22"
        }]
    }

    md = BriefingEngine.render_markdown(briefing_data)
    assert "# Board Briefing" in md
    assert "CVE-2024-3094" in md
    assert "Alan Vo (alanvo@gmail.com)" in md
