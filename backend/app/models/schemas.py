from datetime import datetime
from typing import Any, Dict, Generic, List, Literal, Optional, TypeVar
from pydantic import BaseModel, ConfigDict, Field

class ORMModel(BaseModel):
    model_config = ConfigDict(from_attributes=True)

class UserProfile(ORMModel):
    id: str; email: str; username: str; full_name: str; role: str; is_active: bool; created_at: datetime

class AuthStatusResponse(BaseModel):
    authenticated: bool; user: Optional[UserProfile] = None; csrf_token: Optional[str] = None; demo_mode: bool = False; oidc_configured: bool = False

class DemoLoginRequest(BaseModel):
    role: Literal['viewer', 'analyst', 'admin'] = 'analyst'

T = TypeVar('T')
class PaginatedResponse(BaseModel, Generic[T]):
    items: List[T]; total: int; page: int; page_size: int; total_pages: int

class AffectedPackage(BaseModel):
    component: str = Field(..., min_length=1); version_range: str = Field(..., min_length=1); fixed_version: Optional[str] = None

class IOCItem(BaseModel):
    type: Literal['ipv4', 'ipv6', 'domain', 'url', 'md5', 'sha1', 'sha256', 'cidr']; value: str; defanged: str

class VulnerabilityBase(BaseModel):
    id: str = Field(..., pattern='^(CVE-\\d{4}-\\d{4,8}|GHSA-[a-z0-9\\-]+|[A-Z0-9\\-]+)$')
    title: str = Field(..., min_length=3); description: str = Field(..., min_length=5)
    severity: Literal['critical', 'high', 'medium', 'low']
    cvss_v3_score: float = Field(ge=0.0, le=10.0, default=0.0); cvss_v3_vector: Optional[str] = None
    epss_score: float = Field(ge=0.0, le=1.0, default=0.0); is_cisa_kev: bool = False; cwe_id: Optional[str] = None
    affected_packages: List[AffectedPackage] = Field(default_factory=list)
    iocs: List[IOCItem] = Field(default_factory=list); source: str = 'Manual / NVD'; tags: List[str] = Field(default_factory=list)

class VulnerabilityCreate(VulnerabilityBase): pass
class VulnerabilityResponse(VulnerabilityBase, ORMModel):
    created_at: datetime; updated_at: datetime

class VulnerabilityBatchImportRequest(BaseModel):
    vulnerabilities: List[VulnerabilityCreate]

class VulnerabilityBatchImportResponse(BaseModel):
    imported_count: int; updated_count: int; errors: List[str] = Field(default_factory=list)

class AssetBase(BaseModel):
    name: str; component: str; version: str
    environment: Literal['production', 'staging', 'internal'] = 'production'
    criticality: Literal['tier_1', 'tier_2', 'tier_3'] = 'tier_2'; internet_exposed: bool = False; owner_email: str
    tags: List[str] = Field(default_factory=list)

class AssetCreate(AssetBase): pass
class AssetUpdate(BaseModel):
    name: Optional[str] = None; component: Optional[str] = None; version: Optional[str] = None
    environment: Optional[Literal['production', 'staging', 'internal']] = None
    criticality: Optional[Literal['tier_1', 'tier_2', 'tier_3']] = None
    internet_exposed: Optional[bool] = None; owner_email: Optional[str] = None; tags: Optional[List[str]] = None

class AssetResponse(AssetBase, ORMModel):
    id: str; created_at: datetime; updated_at: datetime

class ScanCreateRequest(BaseModel):
    title: str; target_environment: Optional[Literal['production', 'staging', 'internal']] = None

class ScanFindingResponse(ORMModel):
    id: str; scan_id: str; asset_id: str; vulnerability_id: str
    asset_name: str; asset_component: str; asset_version: str; cve_id: str
    cvss_score: float; epss_score: float; is_cisa_kev: bool; asset_criticality: str
    internet_exposed: bool; composite_risk_score: float; priority_tier: str
    match_reason: str; score_breakdown: Dict[str, Any]; remediation_recommendation: str
    created_at: datetime

class ThreatScanResponse(ORMModel):
    id: str; title: str; target_environment: Optional[str] = None
    scanned_assets_count: int; findings_count: int; critical_count: int
    high_count: int; medium_count: int; low_count: int; created_by: str
    created_at: datetime; findings: Optional[List[ScanFindingResponse]] = None

class MitigationStep(BaseModel):
    phase: Literal['containment', 'remediation', 'verification']
    title: str; description: str; target_asset: str; target_cve: str

class BriefingCreateRequest(BaseModel):
    title: str; target_date: str; scan_id: Optional[str] = None

class SecurityBriefingResponse(ORMModel):
    id: str; title: str; target_date: str; scan_id: Optional[str] = None
    summary_stats: Dict[str, Any]; executive_summary: str
    top_threats: List[Dict[str, Any]]; mitigation_playbook: List[Dict[str, Any]]
    advisory_narrative: Optional[str] = None; advisory_provider: Optional[str] = None
    advisory_disclaimer: Optional[str] = None; created_by: str; created_at: datetime

class AdvisoryGenerateRequest(BaseModel):
    briefing_id: str

class AdvisoryResponse(BaseModel):
    briefing_id: str; advisory_narrative: str; advisory_provider: str; advisory_disclaimer: str

class IOCExtractRequest(BaseModel):
    raw_text: str

class IOCExtractResponse(BaseModel):
    total_found: int; iocs: List[IOCItem]

class AuditLogResponse(ORMModel):
    id: str; actor_email: str; actor_role: str; action: str; resource_type: str
    resource_id: str; details: Dict[str, Any]; ip_address: Optional[str] = None; created_at: datetime

class HealthResponse(BaseModel):
    status: str; app: str; version: str; database_ok: bool; demo_mode: bool
    llm_configured: bool; llm_provider: str; llm_model: str
