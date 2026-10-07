import logging
from typing import Any, Dict, List, Optional
import httpx
from app.core.config import settings
logger = logging.getLogger(__name__)
ADVISORY_DISCLAIMER = 'ADVISORY ONLY: LLM-generated contextual narrative. Non-authoritative security guidance grounded in recorded scan telemetry. Human review required before execution.'

class LLMProviderError(Exception): pass

class LLMService:
    def __init__(self) -> None:
        self.timeout = httpx.Timeout(settings.LLM_TIMEOUT_SECONDS, connect=5.0)

    def _sanitize_error(self, err_msg: str) -> str:
        if settings.LLM_API_KEY and len(settings.LLM_API_KEY) > 3:
            err_msg = err_msg.replace(settings.LLM_API_KEY, '[REDACTED_KEY]')
        return err_msg

    async def _call_openai_compatible(self, system: str, prompt: str) -> str:
        url = f'{settings.LLM_BASE_URL.rstrip("/")}/chat/completions'
        h = {'Content-Type': 'application/json'}
        if settings.LLM_API_KEY: h['Authorization'] = f'Bearer {settings.LLM_API_KEY}'
        body = {'model': settings.LLM_MODEL, 'messages': [{'role': 'system', 'content': system}, {'role': 'user', 'content': prompt}], 'temperature': 0.2, 'max_tokens': 1200}
        async with httpx.AsyncClient(timeout=self.timeout) as c:
            r = await c.post(url, json=body, headers=h)
            r.raise_for_status()
            return r.json()['choices'][0]['message']['content']

    async def _call_anthropic(self, system: str, prompt: str) -> str:
        if not settings.LLM_API_KEY: raise LLMProviderError('LLM_API_KEY is required for Anthropic provider.')
        url = f'{settings.LLM_BASE_URL.rstrip("/")}/v1/messages'
        h = {'x-api-key': settings.LLM_API_KEY, 'anthropic-version': '2023-06-01', 'Content-Type': 'application/json'}
        body = {'model': settings.LLM_MODEL, 'system': system, 'messages': [{'role': 'user', 'content': prompt}], 'max_tokens': 1200, 'temperature': 0.2}
        async with httpx.AsyncClient(timeout=self.timeout) as c:
            r = await c.post(url, json=body, headers=h)
            r.raise_for_status()
            return r.json()['content'][0]['text']

    async def _call_gemini(self, system: str, prompt: str) -> str:
        if not settings.LLM_API_KEY: raise LLMProviderError('LLM_API_KEY is required for Gemini provider.')
        url = f'{settings.LLM_BASE_URL.rstrip("/")}/v1beta/models/{settings.LLM_MODEL}:generateContent?key={settings.LLM_API_KEY}'
        body = {'contents': [{'parts': [{'text': prompt}]}], 'systemInstruction': {'parts': [{'text': system}]}}
        async with httpx.AsyncClient(timeout=self.timeout) as c:
            r = await c.post(url, json=body, headers={'Content-Type': 'application/json'})
            r.raise_for_status()
            return r.json()['candidates'][0]['content']['parts'][0]['text']

    async def _dispatch_chat(self, system: str, prompt: str) -> str:
        p = settings.LLM_PROVIDER.lower()
        try:
            if p in ('openai-compatible', 'ollama'):
                if p == 'openai-compatible' and not settings.LLM_API_KEY and 'localhost' not in settings.LLM_BASE_URL:
                    raise LLMProviderError('LLM_API_KEY is not configured by operator for remote provider.')
                return await self._call_openai_compatible(system, prompt)
            elif p == 'anthropic': return await self._call_anthropic(system, prompt)
            elif p == 'gemini': return await self._call_gemini(system, prompt)
            else: raise LLMProviderError(f"Unsupported LLM_PROVIDER '{settings.LLM_PROVIDER}'.")
        except httpx.HTTPStatusError as e:
            red = self._sanitize_error(str(e))
            logger.error('Upstream LLM HTTP error: %s', red)
            raise LLMProviderError(f'Upstream provider returned status {e.response.status_code}: {red}') from e
        except httpx.TimeoutException as e:
            logger.error('Upstream LLM provider timed out after %ss', settings.LLM_TIMEOUT_SECONDS)
            raise LLMProviderError(f'Upstream LLM provider request timed out ({settings.LLM_TIMEOUT_SECONDS}s).') from e
        except Exception as e:
            red = self._sanitize_error(str(e))
            logger.error('LLM invocation error: %s', red)
            raise LLMProviderError(f'LLM advisory generation failed: {red}') from e

    async def generate_advisory_narrative(self, briefing_title: str, target_date: str, summary_stats: Dict[str, Any], top_threats: List[Dict[str, Any]]) -> Dict[str, str]:
        sys_inst = 'You are a threat intelligence advisory assistant. Provide a grounded technical commentary evaluating provided CVE exposures. Do not fabricate CVEs or metrics beyond the facts supplied.'
        t_lines = [f"- {t['cve_id']} on {t['asset_name']} ({t['asset_component']} v{t['asset_version']}): Risk {t['composite_risk_score']}/100, Tier: {t['priority_tier']}, CVSS {t['cvss_score']}, EPSS {t['epss_score']}, KEV: {t['is_cisa_kev']}, Exposed: {t['internet_exposed']}." for t in top_threats[:5]]
        prompt = f"Review security briefing for {target_date} ('{briefing_title}'):\nSummary: {summary_stats}\nThreats:\n" + '\n'.join(t_lines) + '\nProvide actionable advisory narrative.'
        narrative = await self._dispatch_chat(sys_inst, prompt)
        return {'advisory_narrative': narrative.strip(), 'advisory_provider': f'{settings.LLM_PROVIDER} ({settings.LLM_MODEL})', 'advisory_disclaimer': ADVISORY_DISCLAIMER}

llm_service = LLMService()
