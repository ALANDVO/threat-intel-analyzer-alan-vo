# Product development plan

Each round completes one feature or repair. Future items are planned, not implemented claims.

## Current round

ioc-detection-and-defanging-enhancement

## Roadmap

### cve-normalization-and-ingestion — Deterministic CVE normalization and ingestion

Status: done

Acceptance:
- Ingests vulnerability records with deterministic CVSS v3.1 calculation from metric vectors
- Normalizes severity tiers based on calculated or declared CVSS base scores
- Extracts, defangs and refangs network indicators and file hashes from vulnerability descriptions

Implementation: `backend/app/services/threat_engine.py`, `backend/app/api/vulnerabilities.py`, `backend/app/models/entities.py`, `backend/app/models/schemas.py`

Tests: `backend/tests/test_domain_engines.py`, `backend/tests/test_api_workflows.py`

### asset-exposure-correlation — Asset tech stack exposure correlation and multi-factor risk scoring

Status: done

Acceptance:
- Matches asset component versions against CVE package version constraint expressions
- Computes composite risk scores combining CVSS, EPSS, CISA KEV status, and exposure
- Classifies correlated findings into actionable priority tiers (Critical, High, Medium, Low)

Implementation: `backend/app/services/correlation_engine.py`, `backend/app/api/scans.py`, `backend/app/api/assets.py`

Tests: `backend/tests/test_correlation_and_risk.py`, `backend/tests/test_api_workflows.py`

### briefing-synthesis-and-advisory — Security briefing generation with grounded LLM advisory narrative

Status: done

Acceptance:
- Synthesizes scan results into executive security briefings with phased mitigation playbooks
- Exports structured briefings to standalone Markdown reports with executive metrics
- Provides opt-in grounded advisory narratives using interchangeable LLM adapters with error redaction

Implementation: `backend/app/services/briefing_engine.py`, `backend/app/services/llm_service.py`, `backend/app/api/briefings.py`

Tests: `backend/tests/test_briefing_engine.py`, `backend/tests/test_llm_adapters.py`

### threat-taxonomy-ml-evaluation — Lexical ML threat taxonomy classification and evaluation harness

Status: done

Acceptance:
- Classifies vulnerability text into threat categories using deterministic weighted lexical features
- Evaluates classifier against labeled CVE benchmark calculating precision, recall, and macro F1
- Computes advisory grounding scores measuring factual keyword coverage against source telemetry

Implementation: `backend/app/services/ml_eval.py`, `backend/app/api/ml_eval.py`

Tests: `backend/tests/test_ml_eval.py`

### ioc-detection-and-defanging-enhancement — Enhanced IOC parser and defanger for compressed IPv6 and URL indicators

Status: done

Acceptance:
- IOCParser extracts uncompressed and compressed IPv6 indicators from threat narrative text
- IOCParser defangs IPv6 addresses with bracketed colons to neutralize indicator exploitation
- Refanging accurately restores defanged IPv6 bracketed colons back to valid addresses
- Extracted indicators pass through vulnerability entity ingestion and API endpoints

Implementation: `backend/app/services/threat_engine.py`, `backend/app/api/vulnerabilities.py`

Tests: `backend/tests/test_domain_engines.py`

### cve-bulk-stix-import — STIX 2.1 threat intelligence bundle import and export

Status: planned

Acceptance:
- Ingests STIX 2.1 vulnerability and indicator bundle JSON payloads
- Maps STIX objects to internal VulnerabilityEntity and IOC records
- Exports selected briefings and scan findings as STIX 2.1 bundles

### automated-webhook-alerts — Automated security alert webhooks for critical findings

Status: planned

Acceptance:
- Configures outbound webhook endpoints with HMAC signature verification
- Dispatches real-time event notifications when scans detect critical tier findings
- Provides delivery retry policy with exponential backoff and audit tracking

