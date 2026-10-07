"""End-to-end workflow integration tests: ingestion, correlation scans, briefing generation, and audit logging."""
import pytest


def test_complete_threat_management_workflow(client, auth_headers_and_cookies):
    analyst_creds = auth_headers_and_cookies["analyst"]
    admin_creds = auth_headers_and_cookies["admin"]
    viewer_creds = auth_headers_and_cookies["viewer"]

    # Step 1: Analyst ingests a new critical vulnerability
    new_vuln = {
        "id": "CVE-2024-9999",
        "title": "FastAPI Async Buffer Overflow Vulnerability",
        "description": (
            "Buffer overflow vulnerability in mock parser allows unauthenticated remote code execution. "
            "Reported attacker C2 IP: 198.51.100.99 with sha256 drop hash e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855."
        ),
        "severity": "critical",
        "cvss_v3_score": 9.8,
        "cvss_v3_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "epss_score": 0.85,
        "is_cisa_kev": True,
        "cwe_id": "CWE-120",
        "affected_packages": [
            {"component": "fastapi", "version_range": "< 0.115.0", "fixed_version": "0.115.0"}
        ],
        "iocs": [],  # Will be extracted automatically
        "source": "Security Advisory",
        "tags": ["buffer-overflow", "fastapi"]
    }

    r_create_vuln = client.post(
        "/api/v1/vulnerabilities",
        json=new_vuln,
        cookies=analyst_creds["cookies"],
        headers=analyst_creds["headers"]
    )
    assert r_create_vuln.status_code == 201
    vuln_data = r_create_vuln.json()
    assert vuln_data["id"] == "CVE-2024-9999"
    # Ensure IOC extraction automatically populated IOCs
    assert len(vuln_data["iocs"]) >= 1

    # Step 2: Analyst enrolls an affected infrastructure asset
    asset_payload = {
        "name": "api-gateway-core",
        "component": "fastapi",
        "version": "0.100.0",
        "environment": "production",
        "criticality": "tier_1",
        "internet_exposed": True,
        "owner_email": "infra@test.local",
        "tags": ["core", "edge"]
    }

    r_asset = client.post(
        "/api/v1/assets",
        json=asset_payload,
        cookies=analyst_creds["cookies"],
        headers=analyst_creds["headers"]
    )
    assert r_asset.status_code == 201
    asset_data = r_asset.json()
    assert asset_data["component"] == "fastapi"

    # Step 3: Run correlation scan against production environment
    r_scan = client.post(
        "/api/v1/scans/run",
        json={"title": "Q4 Perimeter Security Scan", "target_environment": "production"},
        cookies=analyst_creds["cookies"],
        headers=analyst_creds["headers"]
    )
    assert r_scan.status_code == 201
    scan_data = r_scan.json()
    assert scan_data["findings_count"] >= 1
    assert scan_data["critical_count"] >= 1

    # Verify correlated finding
    finding = next(f for f in scan_data["findings"] if f["cve_id"] == "CVE-2024-9999")
    assert finding["priority_tier"] == "CRITICAL"
    assert finding["composite_risk_score"] >= 80.0
    assert "Upgrade fastapi" in finding["remediation_recommendation"]

    # Step 4: Viewer can read scan findings and export JSON
    r_export = client.get(
        f"/api/v1/scans/{scan_data['id']}/export",
        cookies=viewer_creds["cookies"],
        headers=viewer_creds["headers"]
    )
    assert r_export.status_code == 200
    export_json = r_export.json()
    assert export_json["scan_id"] == scan_data["id"]
    assert len(export_json["findings"]) >= 1

    # Step 5: Analyst generates Executive Security Briefing
    r_briefing = client.post(
        "/api/v1/briefings/generate",
        json={"title": "Executive Board Briefing", "target_date": "2026-10-07", "scan_id": scan_data["id"]},
        cookies=analyst_creds["cookies"],
        headers=analyst_creds["headers"]
    )
    assert r_briefing.status_code == 201
    briefing_data = r_briefing.json()
    assert "ELEVATED RISK POSTURE" in briefing_data["executive_summary"]
    assert len(briefing_data["mitigation_playbook"]) >= 3

    # Step 6: Viewer exports Markdown report
    r_md = client.get(
        f"/api/v1/briefings/{briefing_data['id']}/export-markdown",
        cookies=viewer_creds["cookies"],
        headers=viewer_creds["headers"]
    )
    assert r_md.status_code == 200
    assert "# Executive Board Briefing" in r_md.text
    assert "Alan Vo" in r_md.text

    # Step 7: Admin verifies immutable audit log records all actions
    r_audit = client.get(
        "/api/v1/audit",
        cookies=admin_creds["cookies"],
        headers=admin_creds["headers"]
    )
    assert r_audit.status_code == 200
    audit_items = r_audit.json()["items"]
    actions = [a["action"] for a in audit_items]
    assert "vulnerability.create" in actions
    assert "asset.create" in actions
    assert "scan.execute" in actions
    assert "briefing.generate" in actions
