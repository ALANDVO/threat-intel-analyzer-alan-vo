import secrets
from enum import Enum
from typing import Optional
from fastapi import HTTPException, status

class UserRole(str, Enum):
    VIEWER = 'viewer'
    ANALYST = 'analyst'
    ADMIN = 'admin'

    @property
    def rank(self) -> int:
        ranks = {UserRole.VIEWER: 1, UserRole.ANALYST: 2, UserRole.ADMIN: 3}
        return ranks.get(self, 0)

    def can_access(self, required_role: 'UserRole') -> bool:
        return self.rank >= required_role.rank

def generate_session_token() -> str:
    return secrets.token_urlsafe(32)

def generate_csrf_token() -> str:
    return secrets.token_urlsafe(32)

def verify_csrf_token(header_token: Optional[str], session_csrf_token: Optional[str]) -> None:
    if not header_token or not session_csrf_token:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail='CSRF token missing from request headers or session.')
    if not secrets.compare_digest(header_token, session_csrf_token):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail='Invalid CSRF token.')
