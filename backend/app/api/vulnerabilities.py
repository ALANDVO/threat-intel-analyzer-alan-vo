import math
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session
from sqlalchemy import or_
from app.api.deps import require_role, verify_csrf
from app.core.database import get_db
from app.core.security import UserRole
from app.models.entities import UserEntity, VulnerabilityEntity
from app.models.schemas import IOCExtractRequest, IOCExtractResponse, PaginatedResponse, VulnerabilityBatchImportRequest, VulnerabilityBatchImportResponse, VulnerabilityCreate, VulnerabilityResponse
from app.services.audit_service import audit_service
from app.services.threat_engine import CVSS31Calculator, IOCParser

router = APIRouter(prefix='/vulnerabilities', tags=['Vulnerabilities'])

def _prep_vuln(p):
    sc, sev = p.cvss_v3_score, p.severity
    if p.cvss_v3_vector and sc == 0.0: sc, sev = CVSS31Calculator.calculate(p.cvss_v3_vector)
    iocs = [i.model_dump() for i in p.iocs] or [i.model_dump() for i in IOCParser.extract_iocs(p.description)]
    pkgs = [pkg.model_dump() for pkg in p.affected_packages]
    return sc, sev, iocs, pkgs

@router.get('', response_model=PaginatedResponse[VulnerabilityResponse])
def list_vulnerabilities(page: int = Query(1, ge=1), page_size: int = Query(10, ge=1, le=100), severity: Optional[str] = None, is_cisa_kev: Optional[bool] = None, search: Optional[str] = None, db: Session = Depends(get_db), current_user: UserEntity = Depends(require_role(UserRole.VIEWER))):
    q = db.query(VulnerabilityEntity)
    if severity: q = q.filter(VulnerabilityEntity.severity == severity.lower())
    if is_cisa_kev is not None: q = q.filter(VulnerabilityEntity.is_cisa_kev == is_cisa_kev)
    if search:
        s = f'%{search}%'
        q = q.filter(or_(VulnerabilityEntity.id.ilike(s), VulnerabilityEntity.title.ilike(s), VulnerabilityEntity.description.ilike(s)))
    tot = q.count()
    items = q.order_by(VulnerabilityEntity.cvss_v3_score.desc(), VulnerabilityEntity.id.asc()).offset((page - 1) * page_size).limit(page_size).all()
    return PaginatedResponse(items=[VulnerabilityResponse.model_validate(v) for v in items], total=tot, page=page, page_size=page_size, total_pages=math.ceil(tot / page_size) if tot > 0 else 1)

@router.get('/{cve_id}', response_model=VulnerabilityResponse)
def get_vulnerability_detail(cve_id: str, db: Session = Depends(get_db), current_user: UserEntity = Depends(require_role(UserRole.VIEWER))):
    if not (v := db.query(VulnerabilityEntity).filter(VulnerabilityEntity.id == cve_id).first()):
        raise HTTPException(status.HTTP_404_NOT_FOUND, f"Vulnerability '{cve_id}' not found.")
    return VulnerabilityResponse.model_validate(v)

@router.post('', response_model=VulnerabilityResponse, status_code=status.HTTP_201_CREATED, dependencies=[Depends(verify_csrf)])
def create_vulnerability(payload: VulnerabilityCreate, db: Session = Depends(get_db), current_user: UserEntity = Depends(require_role(UserRole.ANALYST))):
    if db.query(VulnerabilityEntity).filter(VulnerabilityEntity.id == payload.id).first():
        raise HTTPException(status.HTTP_409_CONFLICT, f"Vulnerability '{payload.id}' already exists.")
    sc, sev, iocs, pkgs = _prep_vuln(payload)
    d = payload.model_dump()
    d.update({'severity': sev, 'cvss_v3_score': sc, 'affected_packages': pkgs, 'iocs': iocs})
    v = VulnerabilityEntity(**d)
    db.add(v); audit_service.log_action(db, current_user, 'vulnerability.create', 'vulnerability', v.id, {'severity': v.severity, 'score': v.cvss_v3_score}); db.commit()
    return VulnerabilityResponse.model_validate(v)

@router.post('/import', response_model=VulnerabilityBatchImportResponse, dependencies=[Depends(verify_csrf)])
def batch_import_vulnerabilities(payload: VulnerabilityBatchImportRequest, db: Session = Depends(get_db), current_user: UserEntity = Depends(require_role(UserRole.ANALYST))):
    imp, upd, errs = 0, 0, []
    for it in payload.vulnerabilities:
        try:
            sc, sev, iocs, pkgs = _prep_vuln(it)
            ex = db.query(VulnerabilityEntity).filter(VulnerabilityEntity.id == it.id).first()
            if ex:
                ex.title, ex.description, ex.severity, ex.cvss_v3_score, ex.cvss_v3_vector, ex.epss_score, ex.is_cisa_kev, ex.cwe_id, ex.affected_packages, ex.iocs = it.title, it.description, sev, sc, it.cvss_v3_vector, it.epss_score, it.is_cisa_kev, it.cwe_id, pkgs, iocs
                upd += 1
            else:
                d = it.model_dump()
                d.update({'severity': sev, 'cvss_v3_score': sc, 'affected_packages': pkgs, 'iocs': iocs})
                db.add(VulnerabilityEntity(**d))
                imp += 1
        except Exception as e: errs.append(f'{it.id}: {str(e)}')
    audit_service.log_action(db, current_user, 'vulnerability.batch_import', 'vulnerability_batch', 'batch', {'imported': imp, 'updated': upd})
    db.commit()
    return VulnerabilityBatchImportResponse(imported_count=imp, updated_count=upd, errors=errs)

@router.delete('/{cve_id}', status_code=status.HTTP_204_NO_CONTENT, dependencies=[Depends(verify_csrf)])
def delete_vulnerability(cve_id: str, db: Session = Depends(get_db), current_user: UserEntity = Depends(require_role(UserRole.ADMIN))):
    if not (v := db.query(VulnerabilityEntity).filter(VulnerabilityEntity.id == cve_id).first()):
        raise HTTPException(status.HTTP_404_NOT_FOUND, f"Vulnerability '{cve_id}' not found.")
    audit_service.log_action(db, current_user, 'vulnerability.delete', 'vulnerability', cve_id, {'title': v.title})
    db.delete(v); db.commit()

@router.post('/extract-iocs', response_model=IOCExtractResponse)
def extract_iocs_from_text(payload: IOCExtractRequest, current_user: UserEntity = Depends(require_role(UserRole.VIEWER))):
    found = IOCParser.extract_iocs(payload.raw_text)
    return IOCExtractResponse(total_found=len(found), iocs=found)
