# Installable web container

This package contains the React web interface for threat-intel-analyzer-alan-vo. It is a **web UI component**, not a complete standalone deployment. Run and configure the backend and authentication services using the repository README and Compose instructions. API URLs are built into the frontend; use a source build if your deployment requires different build-time settings.

```sh
docker pull ghcr.io/alandvo/threat-intel-analyzer-alan-vo-web:latest
docker run --rm -p 127.0.0.1:5173:80 ghcr.io/alandvo/threat-intel-analyzer-alan-vo-web:latest
```

Open http://127.0.0.1:5173. Use the immutable `sha-<full-commit-sha>` tag from the publication workflow for reproducible installations. `latest` tracks the most recently published build.

## Publication

The **Publish web container** workflow builds the existing frontend Dockerfile, starts the image, and checks the HTML and JavaScript asset over HTTP before pushing it to GitHub Container Registry. This smoke test verifies serving the frontend; it does not certify backend integration, SSO, or every application workflow. Publication runs manually or when a GitHub Release is published.

Public repository, standard Ubuntu runner, public container package. No paid runners or external LLM calls are used by this workflow.

Maintainer: Alan Vo <alanvo@gmail.com>
