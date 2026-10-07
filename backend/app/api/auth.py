from datetime import timedelta
from typing import Optional
from fastapi import APIRouter, Cookie, Depends, HTTPException, Request, Response, status
from sqlalchemy.orm import Session
from app.core.config import settings
from app.core.database import get_db
from app.core.oidc import generate_pkce_pair, oidc_service
from app.core.security import UserRole, generate_csrf_token, generate_session_token
from app.models.entities import SessionEntity, UserEntity, ensure_utc, utc_now
from app.models.schemas import AuthStatusResponse, DemoLoginRequest, UserProfile
from app.services.audit_service import audit_service

router = APIRouter(prefix='/auth', tags=['Authentication'])

def _set_cookies(res: Response, sid: str, csrf: str) -> None:
    res.set_cookie(settings.SESSION_COOKIE_NAME, sid, max_age=settings.SESSION_MAX_AGE_SECONDS, httponly=True, secure=settings.COOKIE_SECURE, samesite=settings.COOKIE_SAMESITE, path='/')
    res.set_cookie(settings.CSRF_COOKIE_NAME, csrf, max_age=settings.SESSION_MAX_AGE_SECONDS, httponly=False, secure=settings.COOKIE_SECURE, samesite=settings.COOKIE_SAMESITE, path='/')

def _issue_session(db: Session, user: UserEntity, action: str, details: dict, req: Request, res: Response) -> str:
    stok, ctok = generate_session_token(), generate_csrf_token()
    db.add(SessionEntity(id=stok, user_id=user.id, csrf_token=ctok, expires_at=utc_now() + timedelta(seconds=settings.SESSION_MAX_AGE_SECONDS)))
    audit_service.log_action(db, user, action, 'session', stok[:8] + '...', details, req.client.host if req.client else None)
    db.commit()
    _set_cookies(res, stok, ctok)
    return ctok

@router.get('/me', response_model=AuthStatusResponse)
def get_auth_status(threat_intel_session: Optional[str] = Cookie(None, alias=settings.SESSION_COOKIE_NAME), db: Session = Depends(get_db)):
    demo, oidc = settings.DEMO_MODE and settings.ENVIRONMENT != 'production', bool(settings.OIDC_ISSUER and settings.OIDC_CLIENT_ID)
    if not threat_intel_session: return AuthStatusResponse(authenticated=False, demo_mode=demo, oidc_configured=oidc)
    s = db.query(SessionEntity).filter(SessionEntity.id == threat_intel_session).first()
    if not s or ensure_utc(s.expires_at) <= utc_now(): return AuthStatusResponse(authenticated=False, demo_mode=demo, oidc_configured=oidc)
    u = db.query(UserEntity).filter(UserEntity.id == s.user_id).first()
    if not u or not u.is_active: return AuthStatusResponse(authenticated=False, demo_mode=demo, oidc_configured=oidc)
    return AuthStatusResponse(authenticated=True, user=UserProfile.model_validate(u), csrf_token=s.csrf_token, demo_mode=demo, oidc_configured=oidc)

@router.get('/login')
async def start_oidc_login(response: Response):
    if not settings.OIDC_ISSUER or not settings.OIDC_CLIENT_ID: raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, 'OIDC provider is not configured.')
    v, c = generate_pkce_pair()
    st, nce = generate_session_token(), generate_session_token()
    url = await oidc_service.get_authorization_url(state=st, nonce=nce, code_challenge=c)
    for k, val in [('pkce_verifier', v), ('oidc_state', st), ('oidc_nonce', nce)]: response.set_cookie(k, val, max_age=300, httponly=True, samesite='lax', path='/')
    return {'auth_url': url}

@router.get('/callback')
async def oidc_callback(code: str, state: str, request: Request, response: Response, pkce_verifier: Optional[str] = Cookie(None), oidc_state: Optional[str] = Cookie(None), oidc_nonce: Optional[str] = Cookie(None), db: Session = Depends(get_db)):
    if not pkce_verifier or not oidc_state or state != oidc_state: raise HTTPException(status.HTTP_400_BAD_REQUEST, 'Invalid OIDC state parameter.')
    tokens = await oidc_service.exchange_code(code, pkce_verifier)
    if not (tok := tokens.get('id_token') or tokens.get('access_token')): raise HTTPException(status.HTTP_401_UNAUTHORIZED, 'No token returned by IdP.')
    claims = await oidc_service.validate_token(tok, expected_nonce=oidc_nonce)
    email = claims.get('email') or claims.get('preferred_username') or 'user@domain.local'
    username = claims.get('preferred_username') or email.split('@')[0]
    fullname = claims.get('name') or username
    role = oidc_service.extract_role_from_claims(claims)
    user = db.query(UserEntity).filter(UserEntity.email == email).first()
    if not user:
        user = UserEntity(email=email, username=username, full_name=fullname, role=role.value, is_active=True)
        db.add(user); db.flush()
    else: user.role, user.full_name = role.value, fullname; db.flush()
    _issue_session(db, user, 'auth.oidc_login', {'provider': 'keycloak', 'role': user.role}, request, response)
    for c in ('pkce_verifier', 'oidc_state', 'oidc_nonce'): response.delete_cookie(c, path='/')
    return {'message': 'Authenticated', 'user': UserProfile.model_validate(user)}

@router.post('/logout')
def logout(response: Response, threat_intel_session: Optional[str] = Cookie(None, alias=settings.SESSION_COOKIE_NAME), db: Session = Depends(get_db)):
    if threat_intel_session and (s := db.query(SessionEntity).filter(SessionEntity.id == threat_intel_session).first()):
        if u := db.query(UserEntity).filter(UserEntity.id == s.user_id).first(): audit_service.log_action(db, u, 'auth.logout', 'session', s.id[:8] + '...')
        db.delete(s); db.commit()
    for n in (settings.SESSION_COOKIE_NAME, settings.CSRF_COOKIE_NAME): response.delete_cookie(n, path='/')
    return {'message': 'Logged out successfully'}

@router.post('/demo-login')
def demo_login(payload: DemoLoginRequest, request: Request, response: Response, db: Session = Depends(get_db)):
    if not settings.DEMO_MODE or settings.ENVIRONMENT == 'production': raise HTTPException(status.HTTP_403_FORBIDDEN, 'Demo login is strictly disabled in production.')
    role = payload.role.lower()
    if role not in (UserRole.VIEWER.value, UserRole.ANALYST.value, UserRole.ADMIN.value): raise HTTPException(status.HTTP_400_BAD_REQUEST, 'Invalid role.')
    email = f'demo-{role}@local.threat-intel'
    if not (u := db.query(UserEntity).filter(UserEntity.email == email).first()):
        u = UserEntity(email=email, username=f'demo_{role}', full_name=f'Demo {role.capitalize()}', role=role, is_active=True)
        db.add(u); db.flush()
    else: u.role = role; db.flush()
    ctok = _issue_session(db, u, 'auth.demo_login', {'demo_role': role}, request, response)
    return {'message': f'Demo login active as {role.upper()}', 'user': UserProfile.model_validate(u), 'csrf_token': ctok}
