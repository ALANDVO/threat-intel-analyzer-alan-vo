import base64, hashlib, secrets, urllib.parse
from typing import Any, Dict, Optional, Tuple
import httpx, jwt
from jwt import PyJWKClient
from app.core.config import settings
from app.core.security import UserRole

def generate_pkce_pair() -> Tuple[str, str]:
    vb = secrets.token_bytes(32)
    v = base64.urlsafe_b64encode(vb).decode('utf-8').rstrip('=')
    c = base64.urlsafe_b64encode(hashlib.sha256(v.encode('ascii')).digest()).decode('utf-8').rstrip('=')
    return v, c

class OIDCService:
    def __init__(self):
        self._discovery_cache: Optional[Dict[str, Any]] = None
        self._jwks_client: Optional[PyJWKClient] = None

    async def get_discovery_document(self) -> Dict[str, Any]:
        if self._discovery_cache: return self._discovery_cache
        iss = settings.OIDC_ISSUER.rstrip('/')
        async with httpx.AsyncClient(timeout=10.0) as cl:
            r = await cl.get(f'{iss}/.well-known/openid-configuration')
            r.raise_for_status()
            self._discovery_cache = r.json()
            if ju := self._discovery_cache.get('jwks_uri'): self._jwks_client = PyJWKClient(ju)
            return self._discovery_cache

    async def get_authorization_url(self, state: str, nonce: str, code_challenge: str) -> str:
        d = await self.get_discovery_document()
        ep = d.get('authorization_endpoint')
        if not ep: raise ValueError('authorization_endpoint not found in OIDC discovery.')
        p = {'response_type': 'code', 'client_id': settings.OIDC_CLIENT_ID, 'redirect_uri': settings.OIDC_REDIRECT_URI, 'scope': settings.OIDC_SCOPES, 'state': state, 'nonce': nonce, 'code_challenge': code_challenge, 'code_challenge_method': 'S256'}
        return f'{ep}?{urllib.parse.urlencode(p)}'

    async def exchange_code(self, code: str, code_verifier: str) -> Dict[str, Any]:
        d = await self.get_discovery_document()
        ep = d.get('token_endpoint')
        if not ep: raise ValueError('token_endpoint not found in OIDC discovery.')
        b = {'grant_type': 'authorization_code', 'client_id': settings.OIDC_CLIENT_ID, 'code': code, 'redirect_uri': settings.OIDC_REDIRECT_URI, 'code_verifier': code_verifier}
        if settings.OIDC_CLIENT_SECRET: b['client_secret'] = settings.OIDC_CLIENT_SECRET
        async with httpx.AsyncClient(timeout=10.0) as cl:
            r = await cl.post(ep, data=b)
            r.raise_for_status()
            return r.json()

    async def validate_token(self, token_str: str, expected_nonce: Optional[str] = None) -> Dict[str, Any]:
        d = await self.get_discovery_document()
        iss = d.get('issuer', settings.OIDC_ISSUER)
        if not self._jwks_client:
            if not d.get('jwks_uri'): raise ValueError('jwks_uri not configured in OIDC discovery.')
            self._jwks_client = PyJWKClient(d['jwks_uri'])
        sk = self._jwks_client.get_signing_key_from_jwt(token_str)
        p = jwt.decode(token_str, sk.key, algorithms=['RS256', 'ES256'], audience=settings.OIDC_CLIENT_ID, issuer=iss, options={'require': ['exp', 'iss', 'aud']})
        if expected_nonce and p.get('nonce') != expected_nonce: raise ValueError('OIDC Nonce mismatch detected.')
        return p

    @staticmethod
    def extract_role_from_claims(claims: Dict[str, Any]) -> UserRole:
        roles = []
        if isinstance(claims.get('realm_access'), dict): roles.extend(claims['realm_access'].get('roles', []))
        if isinstance(claims.get('resource_access'), dict):
            ca = claims['resource_access'].get(settings.OIDC_CLIENT_ID, {})
            if isinstance(ca, dict): roles.extend(ca.get('roles', []))
        if isinstance(claims.get('roles'), list): roles.extend(claims['roles'])
        norm = {r.lower() for r in roles if isinstance(r, str)}
        if 'admin' in norm or 'threat-admin' in norm: return UserRole.ADMIN
        if 'analyst' in norm or 'threat-analyst' in norm: return UserRole.ANALYST
        return UserRole.VIEWER

oidc_service = OIDCService()
