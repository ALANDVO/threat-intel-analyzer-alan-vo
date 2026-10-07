import math
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session
from app.api.deps import require_role, verify_csrf
from app.core.database import get_db
from app.core.security import UserRole
from app.models.entities import AssetEntity, ScanFindingEntity, ThreatScanEntity, UserEntity, VulnerabilityEntity
from app.models.schemas import PaginatedResponse, ScanCreateRequest, ScanFindingResponse, ThreatScanResponse
from app.services.audit_service import audit_service
from app.services.correlation_engine import CorrelationEngine

router = APIRouter(prefix='/scans', tags=['Threat Scans'])

@router.post('/run', response_model=ThreatScanResponse, status_code=status.HTTP_201_CREATED, dependencies=[Depends(verify_csrf)])
def run_correlation_scan(payload: ScanCreateRequest, db: Session = Depends(get_db), current_user: UserEntity = Depends(require_role(UserRole.ANALYST))):
    aq = db.query(AssetEntity)
    if payload.target_environment: aq = aq.filter(AssetEntity.environment == payload.target_environment.lower())
    assets = aq.all()
    if not assets: raise HTTPException(status.HTTP_400_BAD_REQUEST, 'No assets available to scan in target environment.')
    findings = [f for a in assets for f in CorrelationEngine.correlate_asset_with_vulnerabilities(a, db.query(VulnerabilityEntity).all())]
    ct = {t.lower(): sum(1 for f in findings if f['priority_tier'] == t) for t in ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW')}
    s = ThreatScanEntity(title=payload.title, target_environment=payload.target_environment, scanned_assets_count=len(assets), findings_count=len(findings), critical_count=ct['critical'], high_count=ct['high'], medium_count=ct['medium'], low_count=ct['low'], created_by=current_user.email)
    db.add(s); db.flush()
    f_ents = [ScanFindingEntity(scan_id=s.id, **rf) for rf in findings]
    db.add_all(f_ents)
    audit_service.log_action(db, current_user, 'scan.execute', 'threat_scan', s.id, {'assets': len(assets), 'findings': len(findings)})
    db.commit()
    res = ThreatScanResponse.model_validate(s)
    res.findings = [ScanFindingResponse.model_validate(f) for f in f_ents]
    return res

@router.get('', response_model=PaginatedResponse[ThreatScanResponse])
def list_scans(page: int = Query(1, ge=1), page_size: int = Query(10, ge=1, le=100), db: Session = Depends(get_db), current_user: UserEntity = Depends(require_role(UserRole.VIEWER))):
    q = db.query(ThreatScanEntity).order_by(ThreatScanEntity.created_at.desc())
    tot = q.count()
    items = q.offset((page - 1) * page_size).limit(page_size).all()
    return PaginatedResponse(items=[ThreatScanResponse.model_validate(s) for s in items], total=tot, page=page, page_size=page_size, total_pages=math.ceil(tot / page_size) if tot > 0 else 1)

@router.get('/{scan_id}', response_model=ThreatScanResponse)
def get_scan_report(scan_id: str, db: Session = Depends(get_db), current_user: UserEntity = Depends(require_role(UserRole.VIEWER))):
    s = db.query(ThreatScanEntity).filter(ThreatScanEntity.id == scan_id).first()
    if not s: raise HTTPException(status.HTTP_404_NOT_FOUND, f"Scan '{scan_id}' not found.")
    res = ThreatScanResponse.model_validate(s)
    res.findings = [ScanFindingResponse.model_validate(f) for f in db.query(ScanFindingEntity).filter(ScanFindingEntity.scan_id == scan_id).order_by(ScanFindingEntity.composite_risk_score.desc()).all()]
    return res

@router.get('/{scan_id}/export')
def export_scan_findings(scan_id: str, db: Session = Depends(get_db), current_user: UserEntity = Depends(require_role(UserRole.VIEWER))):
    s = db.query(ThreatScanEntity).filter(ThreatScanEntity.id == scan_id).first()
    if not s: raise HTTPException(status.HTTP_404_NOT_FOUND, f"Scan '{scan_id}' not found.")
    findings = db.query(ScanFindingEntity).filter(ScanFindingEntity.scan_id == scan_id).order_by(ScanFindingEntity.composite_risk_score.desc()).all()
    return {'scan_id': s.id, 'title': s.title, 'exported_at': s.created_at.isoformat(), 'total_findings': len(findings), 'findings': [ScanFindingResponse.model_validate(f).model_dump() for f in findings]}
