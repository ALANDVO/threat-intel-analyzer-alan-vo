import math
from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from sqlalchemy.orm import Session
from app.api.deps import require_role, verify_csrf
from app.core.database import get_db
from app.core.security import UserRole
from app.models.entities import ScanFindingEntity, SecurityBriefingEntity, ThreatScanEntity, UserEntity
from app.models.schemas import AdvisoryResponse, BriefingCreateRequest, PaginatedResponse, SecurityBriefingResponse
from app.services.audit_service import audit_service
from app.services.briefing_engine import BriefingEngine
from app.services.llm_service import LLMProviderError, llm_service

router = APIRouter(prefix='/briefings', tags=['Security Briefings'])

def _get_briefing(db: Session, bid: str) -> SecurityBriefingEntity:
    if not (b := db.query(SecurityBriefingEntity).filter(SecurityBriefingEntity.id == bid).first()):
        raise HTTPException(status.HTTP_404_NOT_FOUND, f"Briefing '{bid}' not found.")
    return b

@router.post('/generate', response_model=SecurityBriefingResponse, status_code=status.HTTP_201_CREATED, dependencies=[Depends(verify_csrf)])
def generate_briefing(payload: BriefingCreateRequest, db: Session = Depends(get_db), current_user: UserEntity = Depends(require_role(UserRole.ANALYST))) -> SecurityBriefingResponse:
    scan = db.query(ThreatScanEntity).filter(ThreatScanEntity.id == payload.scan_id).first() if payload.scan_id else db.query(ThreatScanEntity).order_by(ThreatScanEntity.created_at.desc()).first()
    if not scan: raise HTTPException(status.HTTP_400_BAD_REQUEST, 'No scan report found to generate briefing from.')
    findings = db.query(ScanFindingEntity).filter(ScanFindingEntity.scan_id == scan.id).order_by(ScanFindingEntity.composite_risk_score.desc()).all()
    d = BriefingEngine.generate_briefing(title=payload.title, target_date=payload.target_date, scan=scan, findings=findings, created_by=current_user.email)
    b = SecurityBriefingEntity(**d)
    db.add(b); db.flush()
    audit_service.log_action(db, current_user, 'briefing.generate', 'security_briefing', b.id, {'scan_id': scan.id, 'title': b.title})
    db.commit()
    return SecurityBriefingResponse.model_validate(b)

@router.get('', response_model=PaginatedResponse[SecurityBriefingResponse])
def list_briefings(page: int = Query(1, ge=1), page_size: int = Query(10, ge=1, le=100), db: Session = Depends(get_db), current_user: UserEntity = Depends(require_role(UserRole.VIEWER))) -> PaginatedResponse[SecurityBriefingResponse]:
    q = db.query(SecurityBriefingEntity).order_by(SecurityBriefingEntity.created_at.desc())
    tot = q.count()
    items = q.offset((page - 1) * page_size).limit(page_size).all()
    return PaginatedResponse(items=[SecurityBriefingResponse.model_validate(b) for b in items], total=tot, page=page, page_size=page_size, total_pages=math.ceil(tot / page_size) if tot > 0 else 1)

@router.get('/{briefing_id}', response_model=SecurityBriefingResponse)
def get_briefing(briefing_id: str, db: Session = Depends(get_db), current_user: UserEntity = Depends(require_role(UserRole.VIEWER))) -> SecurityBriefingResponse:
    return SecurityBriefingResponse.model_validate(_get_briefing(db, briefing_id))

@router.post('/{briefing_id}/advisory', response_model=AdvisoryResponse, dependencies=[Depends(verify_csrf)])
async def generate_advisory_narrative(briefing_id: str, db: Session = Depends(get_db), current_user: UserEntity = Depends(require_role(UserRole.ANALYST))) -> AdvisoryResponse:
    b = _get_briefing(db, briefing_id)
    try:
        adv = await llm_service.generate_advisory_narrative(briefing_title=b.title, target_date=b.target_date, summary_stats=b.summary_stats or {}, top_threats=b.top_threats or [])
    except LLMProviderError as e: raise HTTPException(status.HTTP_502_BAD_GATEWAY, str(e))
    b.advisory_narrative, b.advisory_provider, b.advisory_disclaimer = adv['advisory_narrative'], adv['advisory_provider'], adv['advisory_disclaimer']
    audit_service.log_action(db, current_user, 'briefing.advisory_analysis', 'security_briefing', b.id, {'provider': b.advisory_provider})
    db.commit()
    return AdvisoryResponse(briefing_id=b.id, advisory_narrative=b.advisory_narrative, advisory_provider=b.advisory_provider, advisory_disclaimer=b.advisory_disclaimer)

@router.get('/{briefing_id}/export-markdown')
def export_briefing_markdown(briefing_id: str, db: Session = Depends(get_db), current_user: UserEntity = Depends(require_role(UserRole.VIEWER))):
    b = _get_briefing(db, briefing_id)
    d = {'title': b.title, 'target_date': b.target_date, 'created_by': b.created_by, 'summary_stats': b.summary_stats, 'executive_summary': b.executive_summary, 'top_threats': b.top_threats, 'mitigation_playbook': b.mitigation_playbook, 'advisory_narrative': b.advisory_narrative, 'advisory_disclaimer': b.advisory_disclaimer}
    md = BriefingEngine.render_markdown(d)
    return Response(content=md, media_type='text/markdown', headers={'Content-Disposition': f'attachment; filename="security_briefing_{b.target_date.replace(" ", "_")}.md"'})
