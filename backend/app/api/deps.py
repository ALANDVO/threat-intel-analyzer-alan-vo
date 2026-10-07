from datetime import datetime, timezone
from typing import Callable, Optional
from fastapi import Cookie, Depends, Header, HTTPException, Request, status
from sqlalchemy.orm import Session
from app.core.config import settings
from app.core.database import get_db
from app.core.security import UserRole, verify_csrf_token
from app.models.entities import SessionEntity, UserEntity, ensure_utc

def get_current_session(threat_intel_session: Optional[str]=Cookie(None, alias=settings.SESSION_COOKIE_NAME), db: Session=Depends(get_db)) -> SessionEntity:
    if not threat_intel_session:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='Authentication required. No session cookie provided.')
    session_record = db.query(SessionEntity).filter(SessionEntity.id == threat_intel_session).first()
    if not session_record:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='Invalid or terminated session.')
    now = datetime.now(timezone.utc)
    if ensure_utc(session_record.expires_at) <= now:
        db.delete(session_record)
        db.commit()
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='Session expired. Please log in again.')
    return session_record

def get_current_user(session_record: SessionEntity=Depends(get_current_session), db: Session=Depends(get_db)) -> UserEntity:
    user = db.query(UserEntity).filter(UserEntity.id == session_record.user_id).first()
    if not user or not user.is_active:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='User account is deactivated or missing.')
    return user

def verify_csrf(request: Request, session_record: SessionEntity=Depends(get_current_session), x_csrf_token: Optional[str]=Header(None, alias='X-CSRF-Token')) -> None:
    if request.method in ('POST', 'PUT', 'DELETE', 'PATCH'):
        verify_csrf_token(x_csrf_token, session_record.csrf_token)

def require_role(min_role: UserRole) -> Callable:

    def role_checker(user: UserEntity=Depends(get_current_user)) -> UserEntity:
        user_role = UserRole(user.role.lower())
        if not user_role.can_access(min_role):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=f"Operation requires '{min_role.value}' role or higher. Current role: '{user.role}'.")
        return user
    return role_checker
