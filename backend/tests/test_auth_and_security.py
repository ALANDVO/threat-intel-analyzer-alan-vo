"""Security and authorization tests: unauthenticated rejection, role denial, CSRF protection, and startup guards."""
import pytest
from app.core.config import Settings, settings


def test_startup_guard_refuses_demo_mode_in_production():
    prod_settings = Settings(
        ENVIRONMENT="production",
        DEMO_MODE=True,
        OIDC_ISSUER="https://keycloak.example.com/realms/threat-intel",
        OIDC_CLIENT_ID="threat-intel-app"
    )
    with pytest.raises(RuntimeError) as exc_info:
        prod_settings.validate_runtime_guards()
    assert "DEMO_MODE is strictly prohibited in production" in str(exc_info.value)


def test_startup_guard_refuses_empty_oidc_when_demo_false():
    missing_oidc_settings = Settings(
        ENVIRONMENT="development",
        DEMO_MODE=False,
        OIDC_ISSUER="",
        OIDC_CLIENT_ID=""
    )
    with pytest.raises(RuntimeError) as exc_info:
        missing_oidc_settings.validate_runtime_guards()
    assert "OIDC configuration missing" in str(exc_info.value)


def test_unauthenticated_rejection_data_endpoints(client):
    # Missing session cookie -> 401
    r_vuln = client.get("/api/v1/vulnerabilities")
    assert r_vuln.status_code == 401

    r_asset = client.get("/api/v1/assets")
    assert r_asset.status_code == 401

    r_scans = client.get("/api/v1/scans")
    assert r_scans.status_code == 401


def test_role_denial_viewer_cannot_mutate(client, auth_headers_and_cookies):
    viewer_creds = auth_headers_and_cookies["viewer"]

    new_vuln = {
        "id": "CVE-2025-99999",
        "title": "Unauthorized attempt",
        "description": "Testing RBAC boundary",
        "severity": "low",
        "cvss_v3_score": 2.0
    }

    resp = client.post(
        "/api/v1/vulnerabilities",
        json=new_vuln,
        cookies=viewer_creds["cookies"],
        headers=viewer_creds["headers"]
    )
    assert resp.status_code == 403
    assert "analyst" in resp.json()["detail"].lower()


def test_role_denial_analyst_cannot_access_audit_or_delete(client, auth_headers_and_cookies):
    analyst_creds = auth_headers_and_cookies["analyst"]

    # Analyst cannot view audit log
    r_audit = client.get(
        "/api/v1/audit",
        cookies=analyst_creds["cookies"],
        headers=analyst_creds["headers"]
    )
    assert r_audit.status_code == 403
    assert "admin" in r_audit.json()["detail"].lower()

    # Analyst cannot delete vulnerability
    r_del = client.delete(
        "/api/v1/vulnerabilities/CVE-2024-3094",
        cookies=analyst_creds["cookies"],
        headers=analyst_creds["headers"]
    )
    assert r_del.status_code == 403


def test_csrf_protection_rejects_missing_or_mismatched_token(client, auth_headers_and_cookies):
    analyst_creds = auth_headers_and_cookies["analyst"]

    payload = {
        "name": "gateway-test",
        "component": "envoy",
        "version": "1.24.0",
        "environment": "production",
        "criticality": "tier_1",
        "internet_exposed": True,
        "owner_email": "ops@test.local",
        "tags": []
    }

    # Missing X-CSRF-Token header -> 403
    resp_no_csrf = client.post(
        "/api/v1/assets",
        json=payload,
        cookies=analyst_creds["cookies"]
    )
    assert resp_no_csrf.status_code == 403
    assert "csrf" in resp_no_csrf.json()["detail"].lower()

    # Mismatched X-CSRF-Token header -> 403
    resp_bad_csrf = client.post(
        "/api/v1/assets",
        json=payload,
        cookies=analyst_creds["cookies"],
        headers={"X-CSRF-Token": "tampered-token-value"}
    )
    assert resp_bad_csrf.status_code == 403


def test_demo_login_and_logout_lifecycle(client):
    # Demo login as analyst
    r_login = client.post("/api/v1/auth/demo-login", json={"role": "analyst"})
    assert r_login.status_code == 200
    data = r_login.json()
    assert data["user"]["role"] == "analyst"
    assert "csrf_token" in data

    session_cookie = r_login.cookies.get(settings.SESSION_COOKIE_NAME)
    csrf_cookie = r_login.cookies.get(settings.CSRF_COOKIE_NAME)
    assert session_cookie is not None
    assert csrf_cookie is not None

    # Verify session via /auth/me
    r_me = client.get("/api/v1/auth/me", cookies={settings.SESSION_COOKIE_NAME: session_cookie})
    assert r_me.status_code == 200
    me_data = r_me.json()
    assert me_data["authenticated"] is True
    assert me_data["user"]["role"] == "analyst"

    # Explicit logout
    r_logout = client.post("/api/v1/auth/logout", cookies={settings.SESSION_COOKIE_NAME: session_cookie})
    assert r_logout.status_code == 200

    # Session is now invalid
    r_me_after = client.get("/api/v1/auth/me", cookies={settings.SESSION_COOKIE_NAME: session_cookie})
    assert r_me_after.json()["authenticated"] is False
