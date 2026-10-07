from typing import Any, Dict, Optional
from sqlalchemy.orm import Session
from app.models.entities import AuditLogEntity, UserEntity

class AuditService:

    @staticmethod
    def log_action(db: Session, actor: UserEntity, action: str, resource_type: str, resource_id: str, details: Optional[Dict[str, Any]]=None, ip_address: Optional[str]=None) -> AuditLogEntity:
        audit_entry = AuditLogEntity(actor_email=actor.email, actor_role=actor.role, action=action, resource_type=resource_type, resource_id=resource_id, details=details or {}, ip_address=ip_address)
        db.add(audit_entry)
        return audit_entry
audit_service = AuditService()
