"""Tests for multi-provider LLM adapters with mocked network responses and error redaction."""
import json
import pytest
import httpx
from app.core.config import settings
from app.services.llm_service import LLMProviderError, LLMService


@pytest.mark.asyncio
async def test_openai_compatible_adapter(monkeypatch):
    settings.LLM_PROVIDER = "openai-compatible"
    settings.LLM_API_KEY = "mock-secret-key-12345"
    settings.LLM_BASE_URL = "https://llm.chris-vo.com/v1"
    settings.LLM_MODEL = "qwen3.8-27b"

    captured_requests = []

    async def mock_post(client_self, url, **kwargs):
        captured_requests.append({"url": str(url), "json": kwargs.get("json"), "headers": kwargs.get("headers")})
        resp = httpx.Response(
            status_code=200,
            json={
                "choices": [{
                    "message": {"content": "Simulated advisory commentary from mock LLM."}
                }]
            },
            request=httpx.Request("POST", str(url))
        )
        return resp

    monkeypatch.setattr(httpx.AsyncClient, "post", mock_post)

    svc = LLMService()
    result = await svc.generate_advisory_narrative(
        briefing_title="Test Briefing",
        target_date="2026-10-07",
        summary_stats={"total_findings": 1},
        top_threats=[{
            "cve_id": "CVE-2024-3094",
            "asset_name": "prod-box",
            "asset_component": "xz-utils",
            "asset_version": "5.6.0",
            "composite_risk_score": 95.0,
            "priority_tier": "CRITICAL",
            "cvss_score": 10.0,
            "epss_score": 0.88,
            "is_cisa_kev": True,
            "internet_exposed": True
        }]
    )

    assert "Simulated advisory commentary" in result["advisory_narrative"]
    assert "ADVISORY ONLY" in result["advisory_disclaimer"]
    assert len(captured_requests) == 1
    assert captured_requests[0]["headers"]["Authorization"] == "Bearer mock-secret-key-12345"


@pytest.mark.asyncio
async def test_anthropic_adapter(monkeypatch):
    settings.LLM_PROVIDER = "anthropic"
    settings.LLM_API_KEY = "anthropic-mock-key"
    settings.LLM_BASE_URL = "https://api.anthropic.com"
    settings.LLM_MODEL = "claude-3-5-sonnet-20241022"

    async def mock_post(client_self, url, **kwargs):
        return httpx.Response(
            status_code=200,
            json={"content": [{"text": "Anthropic advisory commentary."}]},
            request=httpx.Request("POST", str(url))
        )

    monkeypatch.setattr(httpx.AsyncClient, "post", mock_post)

    svc = LLMService()
    narrative = await svc._call_anthropic("system prompt", "user query")
    assert narrative == "Anthropic advisory commentary."


@pytest.mark.asyncio
async def test_gemini_adapter(monkeypatch):
    settings.LLM_PROVIDER = "gemini"
    settings.LLM_API_KEY = "gemini-mock-key"
    settings.LLM_BASE_URL = "https://generativelanguage.googleapis.com"
    settings.LLM_MODEL = "gemini-1.5-pro"

    async def mock_post(client_self, url, **kwargs):
        return httpx.Response(
            status_code=200,
            json={"candidates": [{"content": {"parts": [{"text": "Gemini advisory commentary."}]}}]},
            request=httpx.Request("POST", str(url))
        )

    monkeypatch.setattr(httpx.AsyncClient, "post", mock_post)

    svc = LLMService()
    narrative = await svc._call_gemini("system prompt", "user query")
    assert narrative == "Gemini advisory commentary."


@pytest.mark.asyncio
async def test_missing_api_key_raises_clear_error():
    settings.LLM_PROVIDER = "anthropic"
    settings.LLM_API_KEY = ""

    svc = LLMService()
    with pytest.raises(LLMProviderError) as exc_info:
        await svc.generate_advisory_narrative("Title", "Today", {}, [])
    assert "LLM_API_KEY is required" in str(exc_info.value)


@pytest.mark.asyncio
async def test_error_redacts_api_key(monkeypatch):
    secret_key = "super-secret-key-xyz987"
    settings.LLM_PROVIDER = "openai-compatible"
    settings.LLM_API_KEY = secret_key
    settings.LLM_BASE_URL = "https://faulty-llm.local"

    async def mock_post(client_self, url, **kwargs):
        raise httpx.ConnectError(f"Connection failed with auth {secret_key}")

    monkeypatch.setattr(httpx.AsyncClient, "post", mock_post)

    svc = LLMService()
    with pytest.raises(LLMProviderError) as exc_info:
        await svc._dispatch_chat("system", "prompt")

    err_str = str(exc_info.value)
    assert secret_key not in err_str
    assert "[REDACTED_KEY]" in err_str
