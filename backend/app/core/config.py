import os
from typing import Literal
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field, field_validator

class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file='.env', env_file_encoding='utf-8', extra='ignore')
    APP_NAME: str = 'Threat Intel Analyzer'
    APP_VERSION: str = '1.0.0'
    ENVIRONMENT: Literal['development', 'test', 'production'] = 'development'
    DEMO_MODE: bool = False
    HOST: str = '127.0.0.1'
    PORT: int = 8000
    DATABASE_URL: str = 'sqlite:///./threat_intel.db'
    SESSION_SECRET_KEY: str = Field(default='dev-secret-key-change-in-prod-min-32-chars')
    SESSION_COOKIE_NAME: str = 'threat_intel_session'
    CSRF_COOKIE_NAME: str = 'threat_intel_csrf'
    SESSION_MAX_AGE_SECONDS: int = 86400
    COOKIE_SECURE: bool = False
    COOKIE_SAMESITE: Literal['lax', 'strict', 'none'] = 'lax'
    OIDC_ISSUER: str = ''
    OIDC_CLIENT_ID: str = ''
    OIDC_CLIENT_SECRET: str = ''
    OIDC_REDIRECT_URI: str = 'http://127.0.0.1:8000/api/v1/auth/callback'
    OIDC_SCOPES: str = 'openid profile email roles'
    LLM_API_KEY: str = ''
    LLM_PROVIDER: Literal['openai-compatible', 'anthropic', 'gemini', 'ollama'] = 'openai-compatible'
    LLM_BASE_URL: str = 'https://llm.chris-vo.com/v1'
    LLM_MODEL: str = 'qwen3.8-27b'
    LLM_TIMEOUT_SECONDS: float = 15.0

    def validate_runtime_guards(self) -> None:
        if self.DEMO_MODE and self.ENVIRONMENT == 'production':
            raise RuntimeError('CRITICAL SECURITY VIOLATION: DEMO_MODE is strictly prohibited in production! Bind to secure OIDC provider.')
        if not self.DEMO_MODE and self.ENVIRONMENT != 'test':
            if not self.OIDC_ISSUER or not self.OIDC_CLIENT_ID:
                raise RuntimeError('OIDC configuration missing: OIDC_ISSUER and OIDC_CLIENT_ID must be set by operator when DEMO_MODE is false. Dev/demo mode never silently switches on.')
settings = Settings()
