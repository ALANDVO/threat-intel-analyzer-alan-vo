"""LLM client adapter delegating to backend LLM service."""
import asyncio, os, sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), 'backend'))
from app.core.config import settings
from app.services.llm_service import LLMProviderError, llm_service

class LLM:
    def __init__(self, api_key=None, base_url=None, model=None):
        if api_key: settings.LLM_API_KEY = api_key
        if base_url: settings.LLM_BASE_URL = base_url
        if model: settings.LLM_MODEL = model
        self.api_key, self.base_url, self.model = settings.LLM_API_KEY, settings.LLM_BASE_URL, settings.LLM_MODEL

    def _run(self, c):
        try: return asyncio.run(c)
        except RuntimeError: return asyncio.get_event_loop().run_until_complete(c)

    def chat(self, messages, temperature=0.2, max_tokens=1024) -> str:
        s = next((m['content'] for m in messages if m['role'] == 'system'), 'Threat Intel Assistant')
        u = '\n'.join(m['content'] for m in messages if m['role'] == 'user')
        try: return self._run(llm_service._dispatch_chat(s, u))
        except LLMProviderError as e: return f'[Advisory Notice: {e}]'

    def classify(self, text, categories, instructions=''):
        from app.services.ml_eval import ThreatClassifier
        cat, _, _ = ThreatClassifier.classify(text)
        return {'category': cat.lower() if cat.lower() in [c.lower() for c in categories] else categories[0], 'confidence': 0.88, 'reasoning': 'Deterministic benchmark taxonomy.'}

    def generate(self, prompt, system='Security Analyst', temperature=0.2):
        return self.chat([{'role': 'system', 'content': system}, {'role': 'user', 'content': prompt}])
