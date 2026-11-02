"""STIX 2.1 import/export API endpoints."""
import json
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from sqlalchemy import or_

from app.api.deps import require_role, verify_csrf
from app.core.database import get_db
from app.core.security import UserRole
from app.models.entities import UserEntity, VulnerabilityEntity, ThreatScanEntity, SecurityBriefingEntity
from app.models.schemas import (
    STIXImportRequest, STIXImportResult, STIXExportRequest, STIXExportResponse
)
from app.services.audit_service import audit_service
from app.services.stix_service import STIXService

router = APIRouter(prefix='/stix', tags=['STIX'])


@router.post('/import', response_model=STIXImportResult, dependencies=[Depends(verify_csrf)])
def import_stix_bundle(
    payload: STIXImportRequest,
    db: Session = Depends(get_db),
    current_user: UserEntity = Depends(require_role(UserRole.ANALYST))
):
    """Import a STIX 2.1 bundle and create vulnerabilities and extract indicators."""
    result = STIXService.import_bundle(payload.bundle)

    imported = 0
    updated = 0
    errors = result.get("errors", [])

    for vuln_data in result.get("vulnerabilities", []):
        try:
            cve_id = vuln_data["id"]
            existing = db.query(VulnerabilityEntity).filter(VulnerabilityEntity.id == cve_id).first()

            if existing:
                # Update existing
                existing.title = vuln_data["title"]
                existing.description = vuln_data["description"]
                existing.severity = vuln_data["severity"]
                existing.cvss_v3_score = vuln_data["cvss_v3_score"]
                existing.cvss_v3_vector = vuln_data["cvss_v3_vector"]
                existing.epss_score = vuln_data["epss_score"]
                existing.is_cisa_kev = vuln_data["is_cisa_kev"]
                existing.cwe_id = vuln_data["cwe_id"]
                existing.affected_packages = vuln_data["affected_packages"]
                existing.iocs = vuln_data["iocs"]
                existing.source = vuln_data["source"]
                existing.tags = vuln_data["tags"]
                updated += 1
            else:
                # Create new
                vuln_entity = VulnerabilityEntity(**vuln_data)
                db.add(vuln_entity)
                imported += 1
        except Exception as e:
            errors.append(f"Failed to save vulnerability {vuln_data.get('id', 'unknown')}: {str(e)}")

    audit_service.log_action(
        db, current_user, 'stix.import', 'stix_bundle', 'import',
        {'imported': imported, 'updated': updated, 'indicators': len(result.get("indicators", [])), 'errors': len(errors)}
    )
    db.commit()

    return STIXImportResult(
        vulnerabilities_imported=imported + updated,
        indicators_extracted=len(result.get("indicators", [])),
        errors=errors
    )


@router.post('/export', response_model=STIXExportResponse)
def export_stix_bundle(
    payload: STIXExportRequest,
    db: Session = Depends(get_db),
    current_user: UserEntity = Depends(require_role(UserRole.VIEWER))
):
    """Export vulnerabilities, scan findings, or briefings as a STIX 2.1 bundle."""
    if payload.scan_id:
        # Export scan findings
        scan = db.query(ThreatScanEntity).filter(ThreatScanEntity.id == payload.scan_id).first()
        if not scan:
            raise HTTPException(status.HTTP_404_NOT_FOUND, f"Scan '{payload.scan_id}' not found.")

        findings = []
        for finding in scan.findings:
            findings.append({
                "vulnerability_id": finding.vulnerability_id,
                "cve_id": finding.cve_id,
                "description": finding.remediation_recommendation,
                "asset_name": finding.asset_name,
                "iocs": []  # IOCs would need to be fetched from vulnerability
            })

        bundle = STIXService.export_scan_findings(findings, payload.title)

    elif payload.briefing_id:
        # Export briefing
        briefing = db.query(SecurityBriefingEntity).filter(SecurityBriefingEntity.id == payload.briefing_id).first()
        if not briefing:
            raise HTTPException(status.HTTP_404_NOT_FOUND, f"Briefing '{payload.briefing_id}' not found.")

        briefing_data = {
            "title": briefing.title,
            "executive_summary": briefing.executive_summary,
            "top_threats": briefing.top_threats or []
        }
        bundle = STIXService.export_briefing(briefing_data)

    else:
        # Export vulnerabilities by IDs or all
        query = db.query(VulnerabilityEntity)
        if payload.vulnerability_ids:
            query = query.filter(VulnerabilityEntity.id.in_(payload.vulnerability_ids))
        vulnerabilities = query.all()

        if not vulnerabilities:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "No vulnerabilities found for export.")

        bundle = STIXService.export_vulnerabilities(vulnerabilities, payload.title)

    audit_service.log_action(
        db, current_user, 'stix.export', 'stix_bundle', 'export',
        {'title': payload.title, 'scan_id': payload.scan_id, 'briefing_id': payload.briefing_id, 'vulnerability_count': len(payload.vulnerability_ids)}
    )

    return STIXExportResponse(bundle=bundle)
