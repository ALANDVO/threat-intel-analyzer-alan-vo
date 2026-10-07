export type Role = "viewer" | "analyst" | "admin";
export interface UserProfile { id: string; email: string; username: string; full_name: string; role: Role; is_active: boolean; created_at: string; }
export interface AuthStatus { authenticated: boolean; user: UserProfile | null; csrf_token: string | null; demo_mode: boolean; oidc_configured: boolean; }
export interface AffectedPackage { component: string; version_range: string; fixed_version?: string; }
export interface IOCItem { type: "ipv4" | "ipv6" | "domain" | "url" | "md5" | "sha1" | "sha256" | "cidr"; value: string; defanged: string; }
export interface Vulnerability {
  id: string; title: string; description: string; severity: "critical" | "high" | "medium" | "low";
  cvss_v3_score: number; cvss_v3_vector?: string; epss_score: number; is_cisa_kev: boolean; cwe_id?: string;
  affected_packages: AffectedPackage[]; iocs: IOCItem[]; source: string; tags: string[]; created_at: string; updated_at: string;
}
export interface Asset {
  id: string; name: string; component: string; version: string;
  environment: "production" | "staging" | "internal"; criticality: "tier_1" | "tier_2" | "tier_3";
  internet_exposed: boolean; owner_email: string; tags: string[]; created_at: string; updated_at: string;
}
export interface ScoreBreakdown {
  cvss_component: number; epss_component: number; cisa_kev_boost: number; exposure_boost: number;
  raw_subtotal: number; criticality_multiplier: number; final_score: number;
}
export interface ScanFinding {
  id: string; scan_id: string; asset_id: string; vulnerability_id: string;
  asset_name: string; asset_component: string; asset_version: string; cve_id: string;
  cvss_score: number; epss_score: number; is_cisa_kev: boolean; asset_criticality: string;
  internet_exposed: boolean; composite_risk_score: number; priority_tier: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
  match_reason: string; score_breakdown: ScoreBreakdown; remediation_recommendation: string; created_at: string;
}
export interface ThreatScan {
  id: string; title: string; target_environment?: string;
  scanned_assets_count: number; findings_count: number; critical_count: number; high_count: number;
  medium_count: number; low_count: number; created_by: string; created_at: string; findings?: ScanFinding[];
}
export interface MitigationStep {
  phase: "containment" | "remediation" | "verification"; title: string; description: string; target_asset: string; target_cve: string;
}
export interface SecurityBriefing {
  id: string; title: string; target_date: string; scan_id?: string;
  summary_stats: { total_findings: number; critical_count: number; high_count: number; medium_count: number; low_count: number; cisa_kev_active_count: number; internet_exposed_count: number; average_composite_score: number; scanned_assets_count: number; scan_title?: string; };
  executive_summary: string;
  top_threats: Array<{ cve_id: string; asset_name: string; asset_component: string; asset_version: string; composite_risk_score: number; priority_tier: string; cvss_score: number; epss_score: number; is_cisa_kev: boolean; internet_exposed: boolean; match_reason: string; remediation: string; }>;
  mitigation_playbook: MitigationStep[]; advisory_narrative?: string; advisory_provider?: string; advisory_disclaimer?: string; created_by: string; created_at: string;
}
export interface AuditLog {
  id: string; actor_email: string; actor_role: string; action: string; resource_type: string; resource_id: string; details: Record<string, any>; ip_address?: string; created_at: string;
}
export interface PaginatedResponse<T> { items: T[]; total: number; page: number; page_size: number; total_pages: number; }
export interface MLEvalResult {
  sample_count: number; accuracy: number; macro_f1: number; category_f1: Record<string, number>; baseline_model: string;
}
