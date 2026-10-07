from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response
from app.api import assets, audit, auth, briefings, health, ml_eval, scans, vulnerabilities
from app.core.config import settings
from app.core.database import SessionLocal, init_db
from app.models.entities import AssetEntity, VulnerabilityEntity

def seed_sample_intel() -> None:
    db = SessionLocal()
    try:
        if db.query(VulnerabilityEntity).count() == 0:
            cves = [
                {'id': 'CVE-2024-3094', 'title': 'XZ Utils Backdoor (liblzma)', 'description': 'Upstream xz backdoor intercepts sshd.', 'severity': 'critical', 'cvss_v3_score': 10.0, 'cvss_v3_vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H', 'epss_score': 0.88, 'is_cisa_kev': True, 'cwe_id': 'CWE-506', 'affected_packages': [{'component': 'xz-utils', 'version_range': '>= 5.6.0, <= 5.6.1', 'fixed_version': '5.6.1-2'}], 'iocs': [{'type': 'ipv4', 'value': '198.51.100.42', 'defanged': '198[.]51[.]100[.]42'}], 'source': 'CISA', 'tags': ['backdoor']},
                {'id': 'CVE-2021-44228', 'title': 'Apache Log4j2 JNDI RCE', 'description': 'Log4j2 JNDI lookup enables remote code execution.', 'severity': 'critical', 'cvss_v3_score': 10.0, 'cvss_v3_vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H', 'epss_score': 0.97, 'is_cisa_kev': True, 'cwe_id': 'CWE-502', 'affected_packages': [{'component': 'log4j', 'version_range': '>= 2.0.0, < 2.15.0', 'fixed_version': '2.16.0'}], 'iocs': [{'type': 'ipv4', 'value': '203.0.113.88', 'defanged': '203[.]0[.]113[.]88'}], 'source': 'CISA KEV', 'tags': ['jndi']},
                {'id': 'CVE-2022-22965', 'title': 'Spring4Shell RCE', 'description': 'Spring MVC arbitrary code execution.', 'severity': 'critical', 'cvss_v3_score': 9.8, 'cvss_v3_vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', 'epss_score': 0.82, 'is_cisa_kev': True, 'cwe_id': 'CWE-94', 'affected_packages': [{'component': 'spring-framework', 'version_range': '>= 5.3.0, < 5.3.18', 'fixed_version': '5.3.18'}], 'source': 'Spring', 'tags': ['rce']}
            ]
            for c in cves: db.add(VulnerabilityEntity(**c))
            db.commit()
        if db.query(AssetEntity).count() == 0:
            ast = [
                {'name': 'edge-proxy-prod', 'component': 'nginx', 'version': '1.20.1', 'environment': 'production', 'criticality': 'tier_1', 'internet_exposed': True, 'owner_email': 'ops@domain.local'},
                {'name': 'auth-backend-prod', 'component': 'xz-utils', 'version': '5.6.0', 'environment': 'production', 'criticality': 'tier_1', 'internet_exposed': True, 'owner_email': 'sec@domain.local'},
                {'name': 'logging-aggregator', 'component': 'log4j', 'version': '2.14.1', 'environment': 'production', 'criticality': 'tier_2', 'internet_exposed': False, 'owner_email': 'platform@domain.local'}
            ]
            for a in ast: db.add(AssetEntity(**a))
            db.commit()
    finally: db.close()

@asynccontextmanager
async def lifespan(app: FastAPI):
    settings.validate_runtime_guards()
    init_db(); seed_sample_intel()
    yield

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        resp: Response = await call_next(request)
        h = {'X-Content-Type-Options': 'nosniff', 'X-Frame-Options': 'DENY', 'X-XSS-Protection': '1; mode=block', 'Referrer-Policy': 'strict-origin-when-cross-origin', 'Content-Security-Policy': "default-src 'self'; frame-ancestors 'none';"}
        for k, v in h.items(): resp.headers[k] = v
        return resp

def create_app() -> FastAPI:
    app = FastAPI(title=settings.APP_NAME, version=settings.APP_VERSION, description='Threat Intelligence Platform', lifespan=lifespan)
    app.add_middleware(SecurityHeadersMiddleware)
    app.add_middleware(CORSMiddleware, allow_origins=['http://127.0.0.1:3000', 'http://localhost:3000', 'http://127.0.0.1:5173', 'http://localhost:5173'], allow_credentials=True, allow_methods=['*'], allow_headers=['*'])
    for r in [auth.router, vulnerabilities.router, assets.router, scans.router, briefings.router, audit.router, ml_eval.router]:
        app.include_router(r, prefix='/api/v1')
    app.include_router(health.router)
    return app

app = create_app()
