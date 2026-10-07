import uuid
from datetime import datetime, timezone
from sqlalchemy import Column as C, String as S, Float as F, Boolean as B, Integer as I, DateTime as DT, Text as T, ForeignKey as FK, JSON as J
from sqlalchemy.orm import relationship
from app.core.database import Base

def utc_now() -> datetime: return datetime.now(timezone.utc)
def ensure_utc(dt: datetime) -> datetime: return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt.astimezone(timezone.utc)
def uid(): return str(uuid.uuid4())
def pk(): return C(S(36), primary_key=True, default=uid)
def dtn(idx=False): return C(DT(timezone=True), default=utc_now, nullable=False, index=idx)

class UserEntity(Base):
    __tablename__ = 'users'
    id = pk()
    email = C(S(255), unique=True, nullable=False, index=True)
    username = C(S(100), unique=True, nullable=False)
    full_name = C(S(255), nullable=False)
    role = C(S(50), nullable=False, default='viewer')
    is_active = C(B, default=True, nullable=False)
    created_at = dtn()
    sessions = relationship('SessionEntity', back_populates='user', cascade='all, delete-orphan')

class SessionEntity(Base):
    __tablename__ = 'sessions'
    id = C(S(64), primary_key=True)
    user_id = C(S(36), FK('users.id', ondelete='CASCADE'), nullable=False, index=True)
    csrf_token = C(S(64), nullable=False)
    created_at = dtn()
    expires_at = C(DT(timezone=True), nullable=False)
    user = relationship('UserEntity', back_populates='sessions')

class VulnerabilityEntity(Base):
    __tablename__ = 'vulnerabilities'
    id = C(S(100), primary_key=True)
    title, description, severity = C(S(500), nullable=False), C(T, nullable=False), C(S(50), nullable=False, index=True)
    cvss_v3_score, cvss_v3_vector = C(F, nullable=False, default=0.0), C(S(200), nullable=True)
    epss_score, is_cisa_kev = C(F, nullable=False, default=0.0), C(B, nullable=False, default=False, index=True)
    cwe_id, affected_packages = C(S(50), nullable=True), C(J, nullable=False, default=list)
    iocs, source, tags = C(J, nullable=False, default=list), C(S(100), nullable=False, default='NVD'), C(J, nullable=False, default=list)
    created_at, updated_at = dtn(), C(DT(timezone=True), default=utc_now, onupdate=utc_now, nullable=False)

class AssetEntity(Base):
    __tablename__ = 'assets'
    id = pk()
    name, component, version = C(S(255), nullable=False, index=True), C(S(100), nullable=False, index=True), C(S(50), nullable=False)
    environment, criticality = C(S(50), nullable=False, default='production', index=True), C(S(50), nullable=False, default='tier_2', index=True)
    internet_exposed, owner_email, tags = C(B, nullable=False, default=False), C(S(255), nullable=False), C(J, nullable=False, default=list)
    created_at, updated_at = dtn(), C(DT(timezone=True), default=utc_now, onupdate=utc_now, nullable=False)

class ThreatScanEntity(Base):
    __tablename__ = 'threat_scans'
    id = pk()
    title, target_environment = C(S(255), nullable=False), C(S(50), nullable=True)
    scanned_assets_count, findings_count = C(I, nullable=False, default=0), C(I, nullable=False, default=0)
    critical_count, high_count = C(I, nullable=False, default=0), C(I, nullable=False, default=0)
    medium_count, low_count = C(I, nullable=False, default=0), C(I, nullable=False, default=0)
    created_by, created_at = C(S(255), nullable=False), dtn()
    findings = relationship('ScanFindingEntity', back_populates='scan', cascade='all, delete-orphan')

class ScanFindingEntity(Base):
    __tablename__ = 'scan_findings'
    id = pk()
    scan_id = C(S(36), FK('threat_scans.id', ondelete='CASCADE'), nullable=False, index=True)
    asset_id, vulnerability_id = C(S(36), nullable=False, index=True), C(S(100), nullable=False, index=True)
    asset_name, asset_component, asset_version = C(S(255), nullable=False), C(S(100), nullable=False), C(S(50), nullable=False)
    cve_id, cvss_score, epss_score = C(S(100), nullable=False, index=True), C(F, nullable=False), C(F, nullable=False)
    is_cisa_kev, asset_criticality, internet_exposed = C(B, nullable=False), C(S(50), nullable=False), C(B, nullable=False)
    composite_risk_score, priority_tier = C(F, nullable=False, index=True), C(S(50), nullable=False, index=True)
    match_reason, score_breakdown, remediation_recommendation = C(T, nullable=False), C(J, nullable=False), C(T, nullable=False)
    created_at = dtn()
    scan = relationship('ThreatScanEntity', back_populates='findings')

class SecurityBriefingEntity(Base):
    __tablename__ = 'security_briefings'
    id = pk()
    title, target_date = C(S(255), nullable=False), C(S(50), nullable=False, index=True)
    scan_id = C(S(36), nullable=True)
    summary_stats, executive_summary = C(J, nullable=False), C(T, nullable=False)
    top_threats, mitigation_playbook = C(J, nullable=False), C(J, nullable=False)
    advisory_narrative, advisory_provider, advisory_disclaimer = C(T, nullable=True), C(S(100), nullable=True), C(T, nullable=True)
    created_by, created_at = C(S(255), nullable=False), dtn()

class AuditLogEntity(Base):
    __tablename__ = 'audit_logs'
    id = pk()
    actor_id, actor_email, actor_role = C(S(36), nullable=True), C(S(255), nullable=False), C(S(50), nullable=False)
    action, resource_type, resource_id = C(S(100), nullable=False, index=True), C(S(100), nullable=False), C(S(100), nullable=False)
    details, ip_address = C(J, nullable=False, default=dict), C(S(50), nullable=True)
    created_at = dtn(idx=True)
