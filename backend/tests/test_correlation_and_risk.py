"""Unit tests for semantic version matching, asset correlation, and composite risk scoring."""
import pytest
from app.models.entities import AssetEntity, VulnerabilityEntity
from app.services.correlation_engine import CorrelationEngine, RiskScorer, VersionMatcher


def test_version_matcher_clauses():
    assert VersionMatcher.is_affected("2.14.1", "< 2.15.0")
    assert not VersionMatcher.is_affected("2.15.0", "< 2.15.0")
    assert VersionMatcher.is_affected("1.20.1", ">= 1.18.0, < 1.25.3")
    assert not VersionMatcher.is_affected("1.26.0", ">= 1.18.0, < 1.25.3")
    assert VersionMatcher.is_affected("5.6.0", ">= 5.6.0, <= 5.6.1")
    assert VersionMatcher.is_affected("1.0.0", "*")


def test_risk_scorer_multi_factor_formula():
    score, tier, breakdown = RiskScorer.calculate_composite_score(
        cvss_score=10.0,      # (10/10)*40 = 40.0
        epss_score=0.8,       # 0.8*25 = 20.0
        is_cisa_kev=True,     # 15.0
        internet_exposed=True, # 10.0
        criticality="tier_1"  # multiplier 1.2
    )
    # Raw sum = 40 + 20 + 15 + 10 = 85.0 * 1.2 = 102 -> clamped to 100.0
    assert score == 100.0
    assert tier == "CRITICAL"
    assert breakdown["cvss_component"] == 40.0
    assert breakdown["epss_component"] == 20.0
    assert breakdown["cisa_kev_boost"] == 15.0
    assert breakdown["exposure_boost"] == 10.0
    assert breakdown["criticality_multiplier"] == 1.2


def test_risk_scorer_low_internal_tier3():
    score, tier, breakdown = RiskScorer.calculate_composite_score(
        cvss_score=4.0,       # (4/10)*40 = 16.0
        epss_score=0.1,       # 0.1*25 = 2.5
        is_cisa_kev=False,    # 0.0
        internet_exposed=False,# 0.0
        criticality="tier_3"  # multiplier 0.8
    )
    # Raw sum = 18.5 * 0.8 = 14.8
    assert score == 14.8
    assert tier == "LOW"


def test_correlation_engine_matching():
    asset = AssetEntity(
        id="asset-1",
        name="web-gateway",
        component="nginx",
        version="1.20.0",
        environment="production",
        criticality="tier_1",
        internet_exposed=True,
        owner_email="ops@test.local",
        tags=[]
    )
    vuln = VulnerabilityEntity(
        id="CVE-2023-44487",
        title="HTTP/2 Rapid Reset",
        description="Denial of service in HTTP/2",
        severity="high",
        cvss_v3_score=7.5,
        epss_score=0.6,
        is_cisa_kev=True,
        affected_packages=[
            {"component": "nginx", "version_range": ">= 1.18.0, < 1.25.3", "fixed_version": "1.25.3"}
        ]
    )

    findings = CorrelationEngine.correlate_asset_with_vulnerabilities(asset, [vuln])
    assert len(findings) == 1
    f = findings[0]
    assert f["cve_id"] == "CVE-2023-44487"
    assert f["asset_component"] == "nginx"
    assert "Upgrade nginx on web-gateway" in f["remediation_recommendation"]
    assert f["composite_risk_score"] > 60.0
