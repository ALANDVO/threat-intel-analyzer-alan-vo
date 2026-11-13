"""STIX 2.1 import/export service for threat intelligence bundles."""
import json
from typing import Dict, List, Optional, Any
from datetime import datetime, timezone

import stix2
from stix2.v21 import Bundle, Vulnerability, Indicator, Malware, Tool, AttackPattern, Relationship, Identity, MarkingDefinition, TLP_WHITE, Software, Report

from app.models.entities import VulnerabilityEntity
from app.models.schemas import IOCItem
from app.services.threat_engine import IOCParser


class STIXService:
    """Service for importing and exporting STIX 2.1 threat intelligence bundles."""

    # Namespace for deterministic ID generation
    NAMESPACE = "threat-intel-analyzer"

    @classmethod
    def _generate_id(cls, type_: str, identifier: str) -> str:
        """Generate deterministic STIX ID."""
        import uuid
        namespace_uuid = uuid.uuid5(uuid.NAMESPACE_DNS, cls.NAMESPACE)
        return f"{type_}--{uuid.uuid5(namespace_uuid, identifier)}"

    @classmethod
    def _create_identity(cls) -> Identity:
        """Create the identity object for this producer."""
        return Identity(
            id=cls._generate_id("identity", "producer"),
            name="Threat Intel Analyzer",
            identity_class="organization",
            description="Automated threat intelligence analysis platform"
        )

    @classmethod
    def _create_marking(cls) -> MarkingDefinition:
        """Create TLP:WHITE marking definition."""
        return TLP_WHITE

    @classmethod
    def import_bundle(cls, bundle_json: Dict[str, Any]) -> Dict[str, Any]:
        """Import a STIX 2.1 bundle and extract vulnerabilities and indicators."""
        vulnerabilities = []
        indicators = []
        errors = []

        try:
            bundle = stix2.parse(bundle_json, version="2.1", allow_custom=True)
        except Exception as e:
            errors.append(f"Failed to parse STIX bundle: {str(e)}")
            return {"vulnerabilities": [], "indicators": [], "errors": errors}

        if not isinstance(bundle, Bundle):
            errors.append("STIX object is not a Bundle")
            return {"vulnerabilities": [], "indicators": [], "errors": errors}

        vuln_objects = []
        indicator_objects = []

        for obj in bundle.objects:
            if obj.type == "vulnerability":
                vuln_objects.append(obj)
            elif obj.type == "indicator":
                indicator_objects.append(obj)

        for vuln in vuln_objects:
            try:
                vuln_entity = cls._parse_vulnerability(vuln)
                if vuln_entity:
                    vulnerabilities.append(vuln_entity)
            except Exception as e:
                errors.append(f"Failed to parse vulnerability {vuln.id}: {str(e)}")

        for indicator in indicator_objects:
            try:
                ioc_items = cls._parse_indicator(indicator)
                indicators.extend(ioc_items)
            except Exception as e:
                errors.append(f"Failed to parse indicator {indicator.id}: {str(e)}")

        return {"vulnerabilities": vulnerabilities, "indicators": indicators, "errors": errors}

    @classmethod
    def _parse_vulnerability(cls, vuln: Vulnerability) -> Optional[Dict[str, Any]]:
        """Parse a STIX Vulnerability object to internal format."""
        cve_id = None
        if vuln.name and vuln.name.startswith("CVE-"):
            cve_id = vuln.name
        elif hasattr(vuln, "external_references") and vuln.external_references:
            for ref in vuln.external_references:
                if ref.get("source_name") == "cve" and ref.get("external_id"):
                    cve_id = ref["external_id"]
                    break

        if not cve_id:
            return None

        description = vuln.description or ""
        cvss_vector = None
        cvss_score = 0.0
        if hasattr(vuln, "external_references") and vuln.external_references:
            for ref in vuln.external_references:
                if ref.get("source_name") == "cvss" and ref.get("description"):
                    cvss_vector = ref["description"]
                    try:
                        from app.services.threat_engine import CVSS31Calculator
                        cvss_score, _ = CVSS31Calculator.calculate(cvss_vector)
                    except Exception:
                        pass

        cwe_id = None
        if hasattr(vuln, "external_references") and vuln.external_references:
            for ref in vuln.external_references:
                if ref.get("source_name") == "cwe" and ref.get("external_id"):
                    cwe_id = ref["external_id"]
                    break

        affected_packages = []
        if hasattr(vuln, "affected_packages") and vuln.affected_packages:
            for pkg in vuln.affected_packages:
                if isinstance(pkg, dict):
                    affected_packages.append({
                        "component": pkg.get("component", ""),
                        "version_range": pkg.get("version_range", ""),
                        "fixed_version": pkg.get("fixed_version")
                    })

        iocs = IOCParser.extract_iocs(description)

        return {
            "id": cve_id,
            "title": vuln.name or cve_id,
            "description": description,
            "severity": "medium",
            "cvss_v3_score": cvss_score,
            "cvss_v3_vector": cvss_vector,
            "epss_score": 0.0,
            "is_cisa_kev": False,
            "cwe_id": cwe_id,
            "affected_packages": affected_packages,
            "iocs": [ioc.model_dump() for ioc in iocs],
            "source": "STIX Import",
            "tags": list(vuln.labels) if hasattr(vuln, "labels") and vuln.labels else []
        }

    @classmethod
    def _parse_indicator(cls, indicator: Indicator) -> List[Dict[str, Any]]:
        """Parse a STIX Indicator object to IOC items."""
        iocs = []
        pattern = getattr(indicator, "pattern", "")
        if not pattern:
            return iocs

        import re

        ipv4_matches = re.findall(r"ipv4-addr:value\s*=\s*'([^']+)'", pattern)
        for ip in ipv4_matches:
            if IOCParser.is_valid_ipv4(ip):
                iocs.append({"type": "ipv4", "value": ip, "defanged": IOCParser.defang(ip)})

        ipv6_matches = re.findall(r"ipv6-addr:value\s*=\s*'([^']+)'", pattern)
        for ip in ipv6_matches:
            if IOCParser.is_valid_ipv6(ip):
                iocs.append({"type": "ipv6", "value": ip, "defanged": IOCParser.defang(ip)})

        domain_matches = re.findall(r"domain-name:value\s*=\s*'([^']+)'", pattern)
        for domain in domain_matches:
            if domain.split('.')[-1].lower() in IOCParser.TLDS:
                iocs.append({"type": "domain", "value": domain, "defanged": IOCParser.defang(domain)})

        url_matches = re.findall(r"url:value\s*=\s*'([^']+)'", pattern)
        for url in url_matches:
            iocs.append({"type": "url", "value": url, "defanged": IOCParser.defang(url)})

        for hash_type, stix_type in [("md5", "md5"), ("sha1", "sha1"), ("sha256", "sha256")]:
            hash_matches = re.findall(rf"file:hashes\.{stix_type}\s*=\s*'([^']+)'", pattern)
            for h in hash_matches:
                iocs.append({"type": hash_type, "value": h.lower(), "defanged": h.lower()})

        return iocs

    @classmethod
    def export_vulnerabilities(cls, vulnerabilities: List[VulnerabilityEntity], title: str = "Threat Intelligence Export") -> Dict[str, Any]:
        """Export vulnerabilities as a STIX 2.1 bundle."""
        objects = []
        identity = cls._create_identity()
        marking = cls._create_marking()
        objects.append(identity)
        objects.append(marking)

        now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

        for vuln in vulnerabilities:
            stix_vuln = cls._create_vulnerability_object(vuln, identity.id, marking.id)
            objects.append(stix_vuln)

            if vuln.iocs:
                for ioc in vuln.iocs:
                    ioc_obj = IOCItem.model_validate(ioc) if isinstance(ioc, dict) else ioc
                    indicator = cls._create_indicator_object(ioc_obj, vuln.id, identity.id, marking.id)
                    if indicator:
                        objects.append(indicator)
                        rel = Relationship(
                            id=cls._generate_id("relationship", f"{indicator.id}-indicates-{stix_vuln.id}"),
                            created=now,
                            modified=now,
                            relationship_type="indicates",
                            source_ref=indicator.id,
                            target_ref=stix_vuln.id,
                            created_by_ref=identity.id,
                            object_marking_refs=[marking.id]
                        )
                        objects.append(rel)

        bundle = Bundle(
            id=cls._generate_id("bundle", title),
            objects=objects,
            allow_custom=True
        )

        try:
            bundle_json = json.loads(bundle.serialize(pretty=True))
        except Exception as e:
            import sys
            print(f"Error serializing STIX bundle: {e}", file=sys.stderr)
            raise
        return bundle_json
    @classmethod
    def _create_vulnerability_object(cls, vuln: VulnerabilityEntity, identity_id: str, marking_id: str) -> Vulnerability:
        """Create a STIX Vulnerability object from internal entity."""
        now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

        external_refs = [{
            "source_name": "cve",
            "external_id": vuln.id,
            "url": f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={vuln.id}"
        }]

        if vuln.cvss_v3_vector:
            external_refs.append({"source_name": "cvss", "description": vuln.cvss_v3_vector})

        if vuln.cwe_id:
            external_refs.append({
                "source_name": "cwe",
                "external_id": vuln.cwe_id,
                "url": f"https://cwe.mitre.org/data/definitions/{vuln.cwe_id.replace('CWE-', '')}.html"
            })

        labels = ["vulnerability"]
        if vuln.severity:
            labels.append(vuln.severity.lower())

        affected_packages = []
        for pkg in vuln.affected_packages:
            if isinstance(pkg, dict):
                affected_packages.append({
                    "component": pkg.get("component", ""),
                    "version_range": pkg.get("version_range", ""),
                    "fixed_version": pkg.get("fixed_version")
                })

        return Vulnerability(
            id=cls._generate_id("vulnerability", vuln.id),
            created=vuln.created_at.isoformat().replace("+00:00", "Z") if vuln.created_at else now,
            modified=vuln.updated_at.isoformat().replace("+00:00", "Z") if vuln.updated_at else now,
            name=vuln.id,
            description=vuln.description,
            labels=labels,
            external_references=external_refs,
            created_by_ref=identity_id,
            object_marking_refs=[marking_id],
            custom_properties={"affected_packages": affected_packages} if affected_packages else None
        )

    @classmethod
    def _create_indicator_object(cls, ioc: IOCItem, vuln_id: str, identity_id: str, marking_id: str) -> Optional[Indicator]:
        """Create a STIX Indicator object from an IOC."""
        now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

        pattern = None
        if ioc.type == "ipv4":
            pattern = f"[ipv4-addr:value = '{ioc.value}']"
        elif ioc.type == "ipv6":
            pattern = f"[ipv6-addr:value = '{ioc.value}']"
        elif ioc.type == "domain":
            pattern = f"[domain-name:value = '{ioc.value}']"
        elif ioc.type == "url":
            pattern = f"[url:value = '{ioc.value}']"
        elif ioc.type in ("md5", "sha1", "sha256"):
            hash_map = {"md5": "MD5", "sha1": "SHA-1", "sha256": "SHA-256"}
            pattern = f"[file:hashes.'{hash_map[ioc.type]}' = '{ioc.value}']"
        elif ioc.type == "cidr":
            pattern = f"[ipv4-addr:value = '{ioc.value}']"

        if not pattern:
            return None

        return Indicator(
            id=cls._generate_id("indicator", f"{vuln_id}-{ioc.type}-{ioc.value}"),
            created=now,
            modified=now,
            name=f"{ioc.type.upper()} indicator for {vuln_id}",
            description=f"{ioc.type.upper()} indicator extracted from {vuln_id}",
            indicator_types=["malicious-activity"],
            pattern=pattern,
            pattern_type="stix",
            valid_from=now,
            created_by_ref=identity_id,
            object_marking_refs=[marking_id]
        )

    @classmethod
    def export_scan_findings(cls, findings: List[Dict[str, Any]], scan_title: str = "Scan Findings Export") -> Dict[str, Any]:
        """Export scan findings as a STIX 2.1 bundle."""
        objects = []
        identity = cls._create_identity()
        marking = cls._create_marking()
        objects.append(identity)
        objects.append(marking)

        now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        vuln_ids_seen = set()

        for finding in findings:
            vuln_id = finding.get("vulnerability_id") or finding.get("cve_id")
            if not vuln_id or vuln_id in vuln_ids_seen:
                continue
            vuln_ids_seen.add(vuln_id)

            stix_vuln = Vulnerability(
                id=cls._generate_id("vulnerability", vuln_id),
                created=now,
                modified=now,
                name=vuln_id,
                description=finding.get("description", ""),
                labels=["vulnerability"],
                external_references=[{
                    "source_name": "cve",
                    "external_id": vuln_id,
                    "url": f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={vuln_id}"
                }],
                created_by_ref=identity.id,
                object_marking_refs=[marking.id]
            )
            objects.append(stix_vuln)

            iocs = finding.get("iocs", [])
            for ioc_data in iocs:
                ioc_obj = IOCItem.model_validate(ioc_data) if isinstance(ioc_data, dict) else ioc_data
                indicator = cls._create_indicator_object(ioc_obj, vuln_id, identity.id, marking.id)
                if indicator:
                    objects.append(indicator)
                    rel = Relationship(
                        id=cls._generate_id("relationship", f"{indicator.id}-indicates-{stix_vuln.id}"),
                        created=now,
                        modified=now,
                        relationship_type="indicates",
                        source_ref=indicator.id,
                        target_ref=stix_vuln.id,
                        created_by_ref=identity.id,
                        object_marking_refs=[marking.id]
                    )
                    objects.append(rel)

            asset_name = finding.get("asset_name")
            if asset_name:
                software = Software(
                    id=cls._generate_id("software", asset_name),
                    name=asset_name,
                    allow_custom=True
                )
                objects.append(software)
                rel = Relationship(
                    id=cls._generate_id("relationship", f"{stix_vuln.id}-affects-{software.id}"),
                    created=now,
                    modified=now,
                    relationship_type="affects",
                    source_ref=stix_vuln.id,
                    target_ref=software.id,
                    created_by_ref=identity.id,
                    object_marking_refs=[marking.id]
                )
                objects.append(rel)

        bundle = Bundle(
            id=cls._generate_id("bundle", scan_title),
            objects=objects,
            allow_custom=True
        )

        try:
            bundle_json = json.loads(bundle.serialize(pretty=True))
        except Exception as e:
            import sys
            print(f"Error serializing STIX bundle: {e}", file=sys.stderr)
            raise
        return bundle_json
    @classmethod
    def export_briefing(cls, briefing_data: Dict[str, Any]) -> Dict[str, Any]:
        """Export a security briefing as a STIX 2.1 bundle."""
        objects = []
        identity = cls._create_identity()
        marking = cls._create_marking()
        objects.append(identity)
        objects.append(marking)

        now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        title = briefing_data.get("title", "Security Briefing")

        # First create vulnerability and indicator objects to collect refs
        report_refs = []
        vuln_objects = []
        indicator_objects = []
        relationship_objects = []

        for threat in briefing_data.get("top_threats", []):
            vuln_id = threat.get("cve_id")
            if not vuln_id:
                continue
            stix_vuln = Vulnerability(
                id=cls._generate_id("vulnerability", vuln_id),
                created=now,
                modified=now,
                name=vuln_id,
                description=threat.get("description", ""),
                labels=["vulnerability", threat.get("severity", "medium").lower()],
                external_references=[{
                    "source_name": "cve",
                    "external_id": vuln_id,
                    "url": f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={vuln_id}"
                }],
                created_by_ref=identity.id,
                object_marking_refs=[marking.id]
            )
            vuln_objects.append(stix_vuln)
            report_refs.append(stix_vuln.id)

            iocs = threat.get("iocs", [])
            for ioc_data in iocs:
                ioc_obj = IOCItem.model_validate(ioc_data) if isinstance(ioc_data, dict) else ioc_data
                indicator = cls._create_indicator_object(ioc_obj, vuln_id, identity.id, marking.id)
                if indicator:
                    indicator_objects.append(indicator)
                    report_refs.append(indicator.id)
                    rel = Relationship(
                        id=cls._generate_id("relationship", f"{indicator.id}-indicates-{stix_vuln.id}"),
                        created=now,
                        modified=now,
                        relationship_type="indicates",
                        source_ref=indicator.id,
                        target_ref=stix_vuln.id,
                        created_by_ref=identity.id,
                        object_marking_refs=[marking.id]
                    )
                    relationship_objects.append(rel)

        # Now create report with object_refs
        report = Report(
            id=cls._generate_id("report", title),
            created=now,
            modified=now,
            name=title,
            description=briefing_data.get("executive_summary", ""),
            published=now,
            report_types=["threat-report"],
            object_refs=report_refs,
            created_by_ref=identity.id,
            object_marking_refs=[marking.id]
        )
        objects.append(report)

        # Add all other objects
        objects.extend(vuln_objects)
        objects.extend(indicator_objects)
        objects.extend(relationship_objects)

        bundle = Bundle(
            id=cls._generate_id("bundle", title),
            objects=objects,
            allow_custom=True
        )

        try:
            bundle_json = json.loads(bundle.serialize(pretty=True))
        except Exception as e:
            import sys
            print(f"Error serializing STIX bundle: {e}", file=sys.stderr)
            raise
        return bundle_json