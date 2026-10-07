# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.0] - 2026-10-07

### Added
- Multi-container deployment architecture via `compose.yaml` with Keycloak 26 IAM broker and persistent storage volumes.
- Production `backend/Dockerfile` and `frontend/Dockerfile` featuring nonroot users, multi-stage builds, and container healthchecks.
- Automated CI pipeline in `.github/workflows/ci.yml` running pytest backend tests, TypeScript typechecking, Vitest frontend tests, and container image builds.
- Machine Learning benchmark and threat classifier evaluation integration with reproducible baseline accuracy and macro F1 metrics.
- Comprehensive security architecture and SAML/OIDC federated identity setup guide.

### Changed
- Standardized portfolio and pyproject metadata with AI/ML workflow summary.
- Refactored frontend and backend source trees for enhanced maintainability and adherence to source size budget.

### Fixed
- Enforced strict session expiration verification and CSRF token binding across write endpoints.

## [1.0.0] - 2026-10-07

### Added
- FastAPI backend with SQLite persistence, transactional mutations, pagination, and audit logging.
- React 18 + TypeScript + Vite responsive dashboard with dark mode UI and real-time API client.
- Deterministic CVSS v3.1 vector calculator adhering to FIRST CVSS v3.1 specification.
- Semantic version range parser and multi-factor asset exposure risk correlation engine.
- Automated executive security briefing engine with mitigation playbooks and Markdown export.
- Multi-provider LLM advisory adapter supporting OpenAI-compatible, Anthropic, Gemini, and Ollama endpoints.
- Secure Keycloak OIDC authorization-code flow with PKCE, SameSite HttpOnly cookies, and role-based access control.

## [0.1.0] - 2026-10-06

### Added
- Prototype command-line threat intelligence ingestion and sample CVE inspection script.
