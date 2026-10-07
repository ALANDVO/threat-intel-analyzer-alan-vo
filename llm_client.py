"""Unified LLM client — works with OpenAI, Claude, Gemini, Ollama, or any OpenAI-compatible API."""
import os, json, requests

class LLM:
    def __init__(self):
        self.api_key = os.environ.get("OPENAI_API_KEY") or os.environ.get("ANTHROPIC_API_KEY") or os.environ.get("GEMINI_API_KEY") or os.environ.get("LLM_API_KEY", "")
        self.base_url = os.environ.get("LLM_BASE_URL", "https://api.openai.com/v1")
        self.model = os.environ.get("LLM_MODEL", "gpt-4o")

    def chat(self, messages, temperature=0.7, max_tokens=2048):
        """Send chat completion request. Returns assistant message string."""
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        payload = {"model": self.model, "messages": messages, "temperature": temperature, "max_tokens": max_tokens}
        r = requests.post(f"{self.base_url}/chat/completions", headers=headers, json=payload, timeout=120)
        r.raise_for_status()
        return r.json()["choices"][0]["message"]["content"]

    def classify(self, text, categories, instructions=""):
        """Classify text into one of the given categories. Returns category + confidence + reasoning."""
        prompt = f"{instructions}Classify the following text into one of these categories: {', '.join(categories)}.\n\nText: {text}\n\nRespond as JSON: {{\"category\": \"...\", \"confidence\": 0.95, \"reasoning\": \"...\", \"key_findings\": [\"...\"]}}"
        raw = self.chat([{"role": "system", "content": "You are an expert classifier. Respond only with valid JSON."}, {"role": "user", "content": prompt}])
        # Extract JSON from response
        start = raw.find("{")
        end = raw.rfind("}") + 1
        try:
            return json.loads(raw[start:end])
        except json.JSONDecodeError:
            return {"category": "unknown", "confidence": 0.0, "reasoning": raw, "key_findings": []}

    def extract(self, text, schema, instructions=""):
        """Extract structured data from text according to schema. Returns dict."""
        prompt = f"{instructions}Extract the following fields from the text:\n{json.dumps(schema, indent=2)}\n\nText: {text}\n\nRespond as JSON matching the schema."
        raw = self.chat([{"role": "system", "content": "You are an expert data extraction engine. Respond only with valid JSON."}, {"role": "user", "content": prompt}])
        start, end = raw.find("{"), raw.rfind("}") + 1
        try:
            return json.loads(raw[start:end])
        except json.JSONDecodeError:
            return {"error": "parse_failed", "raw": raw}

    def generate(self, prompt, system="You are a helpful AI assistant.", temperature=0.7):
        return self.chat([{"role": "system", "content": system}, {"role": "user", "content": prompt}], temperature=temperature)
