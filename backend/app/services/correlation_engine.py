import re
from typing import Any, Dict, List, Tuple
from app.models.entities import AssetEntity, VulnerabilityEntity

class VersionMatcher:
    VERSION_REGEX = re.compile(r'^v?(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:-([a-zA-Z0-9\.]+))?')

    @classmethod
    def parse_version(cls, v_str: str) -> Tuple[int, int, int]:
        if m := cls.VERSION_REGEX.match(v_str.strip().lstrip('v')):
            return int(m.group(1) or 0), int(m.group(2) or 0), int(m.group(3) or 0)
        d = re.findall(r'\d+', v_str)
        return (int(d[0]), int(d[1]) if len(d) > 1 else 0, int(d[2]) if len(d) > 2 else 0) if d else (0, 0, 0)

    @classmethod
    def compare(cls, v1: str, v2: str) -> int:
        t1, t2 = cls.parse_version(v1), cls.parse_version(v2)
        return -1 if t1 < t2 else 1 if t1 > t2 else 0

    @classmethod
    def check_clause(cls, asset_ver: str, clause: str) -> bool:
        c = clause.strip()
        if not c or c == '*': return True
        m = re.match(r'^(<=|>=|<|>|==|=)\s*(.+)$', c)
        if not m: return cls.compare(asset_ver, c) == 0
        op, target = m.group(1), m.group(2).strip()
        cmp = cls.compare(asset_ver, target)
        return cmp < 0 if op == '<' else cmp <= 0 if op == '<=' else cmp > 0 if op == '>' else cmp >= 0 if op == '>=' else cmp == 0

    @classmethod
    def is_affected(cls, asset_version: str, range_spec: str) -> bool:
        clauses = [c.strip() for c in range_spec.split(',') if c.strip()]
        return all(cls.check_clause(asset_version, c) for c in clauses) if clauses else True

class RiskScorer:
    MULTIPLIERS = {'tier_1': 1.2, 'tier_2': 1.0, 'tier_3': 0.8}

    @classmethod
    def calculate_composite_score(cls, cvss_score: float, epss_score: float, is_cisa_kev: bool, internet_exposed: bool, criticality: str) -> Tuple[float, str, Dict[str, Any]]:
        cvss_comp = round(cvss_score / 10.0 * 40.0, 2)
        epss_comp = round(epss_score * 25.0, 2)
        kev_boost = 15.0 if is_cisa_kev else 0.0
        exp_boost = 10.0 if internet_exposed else 0.0
        raw_sum = cvss_comp + epss_comp + kev_boost + exp_boost
        mult = cls.MULTIPLIERS.get(criticality.lower(), 1.0)
        final = round(min(100.0, max(0.0, raw_sum * mult)), 1)
        tier = 'CRITICAL' if final >= 80.0 else 'HIGH' if final >= 60.0 else 'MEDIUM' if final >= 40.0 else 'LOW'
        bd = {'cvss_component': cvss_comp, 'epss_component': epss_comp, 'cisa_kev_boost': kev_boost, 'exposure_boost': exp_boost, 'raw_subtotal': round(raw_sum, 2), 'criticality_multiplier': mult, 'final_score': final}
        return final, tier, bd

class CorrelationEngine:
    @classmethod
    def correlate_asset_with_vulnerabilities(cls, asset: AssetEntity, vulnerabilities: List[VulnerabilityEntity]) -> List[Dict[str, Any]]:
        findings = []
        for v in vulnerabilities:
            for pkg in (v.affected_packages or []):
                if pkg.get('component', '').strip().lower() == asset.component.strip().lower():
                    v_range = pkg.get('version_range', '*')
                    if VersionMatcher.is_affected(asset.version, v_range):
                        fixed = pkg.get('fixed_version') or 'latest patch release'
                        score, tier, bd = RiskScorer.calculate_composite_score(v.cvss_v3_score, v.epss_score, v.is_cisa_kev, asset.internet_exposed, asset.criticality)
                        rem = f'Upgrade {asset.component} on {asset.name} from {asset.version} to {fixed}.'
                        if asset.internet_exposed: rem += ' Restrict public ingress at edge proxy until patched.'
                        findings.append({
                            'asset_id': asset.id, 'vulnerability_id': v.id, 'asset_name': asset.name,
                            'asset_component': asset.component, 'asset_version': asset.version, 'cve_id': v.id,
                            'cvss_score': v.cvss_v3_score, 'epss_score': v.epss_score, 'is_cisa_kev': v.is_cisa_kev,
                            'asset_criticality': asset.criticality, 'internet_exposed': asset.internet_exposed,
                            'composite_risk_score': score, 'priority_tier': tier,
                            'match_reason': f"Component '{asset.component}' version '{asset.version}' matches affected spec '{v_range}'.",
                            'score_breakdown': bd, 'remediation_recommendation': rem
                        })
                        break
        return findings
