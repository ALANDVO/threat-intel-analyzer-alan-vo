from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import text
from app.core.config import settings
from app.core.database import get_db
from app.models.schemas import HealthResponse
router = APIRouter(tags=['Health'])

@router.get('/healthz', response_model=HealthResponse)
def health_check(db: Session=Depends(get_db)) -> HealthResponse:
    db_ok = False
    try:
        db.execute(text('SELECT 1'))
        db_ok = True
    except Exception:
        db_ok = False
    return HealthResponse(status='ok' if db_ok else 'degraded', app=settings.APP_NAME, version=settings.APP_VERSION, database_ok=db_ok, demo_mode=settings.DEMO_MODE, llm_configured=bool(settings.LLM_API_KEY), llm_provider=settings.LLM_PROVIDER, llm_model=settings.LLM_MODEL)
