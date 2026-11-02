"""Tests for STIX 2.1 import/export service."""
import json
from app.services.stix_service import STIXService
from app.models.schemas import IOCItem
from app.models.entities import VulnerabilityEntity
from datetime import datetime, timezone
import stix2
from stix2.v21 import Bundle, Vulnerability, Indicator, Identity, MarkingDefinition, Relationship, Software, Report, TLP_WHITE


def _create_test_bundle(objects):
    """Helper to create a valid STIX bundle for testing."""
    identity = Identity(
        id="identity--00000000-0000-4000-8000-000000000001",
        name="Test Org",
        identity_class="organization"
    )
    marking = TLP_WHITE
    bundle = Bundle(
        id="bundle--00000000-0000-4000-8000-000000000002",
        objects=[identity, marking] + objects,
        allow_custom=True
    )
    return json.loads(bundle.serialize())


def test_stix_import_vulnerability():
    """Test importing a STIX bundle with a vulnerability."""
    vuln = Vulnerability(
        id="vulnerability--00000000-0000-4000-8000-000000000003",
        created="2024-01-01T00:00:00.000Z",
        modified="2024-01-01T00:00:00.000Z",
        name="CVE-2024-12345",
        description="Test vulnerability with IPv4 192.168.1.1 and domain evil.com",
        labels=["vulnerability", "critical"],
        external_references=[
            {"source_name": "cve", "external_id": "CVE-2024-12345"},
            {"source_name": "cvss", "description": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
            {"source_name": "cwe", "external_id": "CWE-787"}
        ],
        allow_custom=True
    )
    bundle_json = _create_test_bundle([vuln])

    result = STIXService.import_bundle(bundle_json)

    assert len(result["errors"]) == 0
    assert len(result["vulnerabilities"]) == 1
    vuln_data = result["vulnerabilities"][0]
    assert vuln_data["id"] == "CVE-2024-12345"
    assert vuln_data["title"] == "CVE-2024-12345"
    assert "Test vulnerability" in vuln_data["description"]
    assert vuln_data["cvss_v3_vector"] == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    assert vuln_data["cwe_id"] == "CWE-787"
    ioc_types = [ioc["type"] for ioc in vuln_data["iocs"]]
    assert "ipv4" in ioc_types
    assert "domain" in ioc_types


def test_stix_import_indicator():
    """Test importing a STIX bundle with indicators."""
    indicator1 = Indicator(
        id="indicator--00000000-0000-4000-8000-000000000004",
        created="2024-01-01T00:00:00.000Z",
        modified="2024-01-01T00:00:00.000Z",
        name="IPv4 indicator",
        description="Malicious IPv4",
        indicator_types=["malicious-activity"],
        pattern="[ipv4-addr:value = '10.0.0.1']",
        pattern_type="stix",
        valid_from="2024-01-01T00:00:00.000Z"
    )
    indicator2 = Indicator(
        id="indicator--00000000-0000-4000-8000-000000000005",
        created="2024-01-01T00:00:00.000Z",
        modified="2024-01-01T00:00:00.000Z",
        name="IPv6 indicator",
        description="Malicious IPv6",
        indicator_types=["malicious-activity"],
        pattern="[ipv6-addr:value = '2001:db8::1']",
        pattern_type="stix",
        valid_from="2024-01-01T00:00:00.000Z"
    )
    indicator3 = Indicator(
        id="indicator--00000000-0000-4000-8000-000000000006",
        created="2024-01-01T00:00:00.000Z",
        modified="2024-01-01T00:00:00.000Z",
        name="SHA256 indicator",
        description="Malicious file",
        indicator_types=["malicious-activity"],
        pattern="[file:hashes.'SHA-256' = '" + "a" * 64 + "']",
        pattern_type="stix",
        valid_from="2024-01-01T00:00:00.000Z"
    )
    bundle_json = _create_test_bundle([indicator1, indicator2, indicator3])

    result = STIXService.import_bundle(bundle_json)

    assert len(result["errors"]) == 0
    assert len(result["indicators"]) >= 2
    indicator_types = [ioc["type"] for ioc in result["indicators"]]
    assert "ipv4" in indicator_types
    assert "ipv6" in indicator_types


def test_stix_export_vulnerabilities():
    """Test exporting vulnerabilities as STIX bundle."""
    vuln = VulnerabilityEntity(
        id="CVE-2024-99999",
        title="Test Export Vulnerability",
        description="Test vulnerability for export with IP 192.0.2.1",
        severity="high",
        cvss_v3_score=8.5,
        cvss_v3_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        epss_score=0.5,
        is_cisa_kev=False,
        cwe_id="CWE-79",
        affected_packages=[{"component": "test-lib", "version_range": ">= 1.0, < 2.0", "fixed_version": "2.0.1"}],
        iocs=[{"type": "ipv4", "value": "192.0.2.1", "defanged": "192[.]0[.]2[.]1"}],
        source="Test",
        tags=["xss"],
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc)
    )

    bundle = STIXService.export_vulnerabilities([vuln], "Test Export")

    assert bundle["type"] == "bundle"
    assert len(bundle["objects"]) >= 3

    vuln_objs = [o for o in bundle["objects"] if o["type"] == "vulnerability"]
    assert len(vuln_objs) == 1
    assert vuln_objs[0]["name"] == "CVE-2024-99999"
    assert "Test vulnerability" in vuln_objs[0]["description"]

    indicator_objs = [o for o in bundle["objects"] if o["type"] == "indicator"]
    assert len(indicator_objs) >= 1
    assert "ipv4-addr:value = '192.0.2.1'" in indicator_objs[0]["pattern"]

    rel_objs = [o for o in bundle["objects"] if o["type"] == "relationship"]
    assert len(rel_objs) >= 1
    assert rel_objs[0]["relationship_type"] == "indicates"


def test_stix_export_scan_findings():
    """Test exporting scan findings as STIX bundle."""
    findings = [
        {
            "vulnerability_id": "CVE-2024-11111",
            "cve_id": "CVE-2024-11111",
            "description": "Finding 1",
            "asset_name": "web-server-01",
            "iocs": [{"type": "ipv4", "value": "192.0.2.10", "defanged": "192[.]0[.]2[.]10"}]
        },
        {
            "vulnerability_id": "CVE-2024-22222",
            "cve_id": "CVE-2024-22222",
            "description": "Finding 2",
            "asset_name": "db-server-01",
            "iocs": []
        }
    ]

    bundle = STIXService.export_scan_findings(findings, "Test Scan Export")

    assert bundle["type"] == "bundle"

    vuln_objs = [o for o in bundle["objects"] if o["type"] == "vulnerability"]
    assert len(vuln_objs) == 2

    software_objs = [o for o in bundle["objects"] if o["type"] == "software"]
    assert len(software_objs) == 2

    rel_objs = [o for o in bundle["objects"] if o["type"] == "relationship" and o["relationship_type"] == "affects"]
    assert len(rel_objs) == 2


def test_stix_export_briefing():
    """Test exporting a briefing as STIX bundle."""
    briefing_data = {
        "title": "Weekly Threat Briefing",
        "executive_summary": "This week saw increased activity...",
        "top_threats": [
            {
                "cve_id": "CVE-2024-33333",
                "description": "Critical RCE in web framework",
                "severity": "critical",
                "iocs": [
                    {"type": "ipv4", "value": "198.51.100.50", "defanged": "198[.]51[.]100[.]50"},
                    {"type": "domain", "value": "malicious.example.com", "defanged": "malicious[.]example[.]com"}
                ]
            }
        ]
    }

    bundle = STIXService.export_briefing(briefing_data)

    assert bundle["type"] == "bundle"

    report_objs = [o for o in bundle["objects"] if o["type"] == "report"]
    assert len(report_objs) == 1
    assert report_objs[0]["name"] == "Weekly Threat Briefing"
    assert report_objs[0]["report_types"] == ["threat-report"]

    vuln_objs = [o for o in bundle["objects"] if o["type"] == "vulnerability"]
    assert len(vuln_objs) == 1
    assert vuln_objs[0]["name"] == "CVE-2024-33333"

    indicator_objs = [o for o in bundle["objects"] if o["type"] == "indicator"]
    assert len(indicator_objs) >= 2

    # Report object_refs includes vuln + indicators (not the report itself)
    assert len(report_objs[0]["object_refs"]) >= 3


def test_stix_roundtrip():
    """Test export then import roundtrip."""
    original_vuln = VulnerabilityEntity(
        id="CVE-2024-44444",
        title="Roundtrip Test",
        description="Test with IP 203.0.113.5 and domain roundtrip.example.com",
        severity="medium",
        cvss_v3_score=6.5,
        cvss_v3_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
        epss_score=0.1,
        is_cisa_kev=False,
        cwe_id="CWE-200",
        affected_packages=[{"component": "roundtrip-lib", "version_range": ">= 1.0", "fixed_version": "1.1"}],
        iocs=[
            {"type": "ipv4", "value": "203.0.113.5", "defanged": "203[.]0[.]113[.]5"},
            {"type": "domain", "value": "roundtrip.example.com", "defanged": "roundtrip[.]example[.]com"}
        ],
        source="Test",
        tags=["roundtrip"],
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc)
    )

    bundle = STIXService.export_vulnerabilities([original_vuln], "Roundtrip Test")
    result = STIXService.import_bundle(bundle)

    assert len(result["errors"]) == 0
    assert len(result["vulnerabilities"]) == 1
    imported = result["vulnerabilities"][0]

    assert imported["id"] == "CVE-2024-44444"
    assert imported["title"] == "CVE-2024-44444"  # STIX Vulnerability name is the CVE ID
    assert imported["cvss_v3_vector"] == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N"
    assert imported["cwe_id"] == "CWE-200"

    # IOCs from description (IPv4) and from indicators (domain would be in indicators, not description)
    ioc_values = {f"{ioc['type']}:{ioc['value']}" for ioc in imported["iocs"]}
    assert "ipv4:203.0.113.5" in ioc_values

    # Indicators are extracted separately
    indicator_types = [ioc["type"] for ioc in result["indicators"]]
    assert "ipv4" in indicator_types
    assert "domain" in indicator_types

    assert len(imported["affected_packages"]) == 1
    assert imported["affected_packages"][0]["component"] == "roundtrip-lib"
