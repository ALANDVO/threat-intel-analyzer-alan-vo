import math
from typing import Optional
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from app.api.deps import require_role
from app.core.database import get_db
from app.core.security import UserRole
from app.models.entities import AuditLogEntity, UserEntity
from app.models.schemas import AuditLogResponse, PaginatedResponse
router = APIRouter(prefix='/audit', tags=['Audit Log'])

@router.get('', response_model=PaginatedResponse[AuditLogResponse])
def list_audit_logs(page: int=Query(1, ge=1), page_size: int=Query(20, ge=1, le=100), action: Optional[str]=Query(None), resource_type: Optional[str]=Query(None), actor_email: Optional[str]=Query(None), db: Session=Depends(get_db), current_user: UserEntity=Depends(require_role(UserRole.ADMIN))) -> PaginatedResponse[AuditLogResponse]:
    query = db.query(AuditLogEntity)
    if action:
        query = query.filter(AuditLogEntity.action == action)
    if resource_type:
        query = query.filter(AuditLogEntity.resource_type == resource_type)
    if actor_email:
        query = query.filter(AuditLogEntity.actor_email.ilike(f'%{actor_email}%'))
    total = query.count()
    items = query.order_by(AuditLogEntity.created_at.desc()).offset((page - 1) * page_size).limit(page_size).all()
    total_pages = math.ceil(total / page_size) if total > 0 else 1
    return PaginatedResponse(items=[AuditLogResponse.model_validate(log) for log in items], total=total, page=page, page_size=page_size, total_pages=total_pages)
