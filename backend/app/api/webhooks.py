"""Webhook API endpoints for automated security alert dispatch."""
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models.entities import WebhookConfigurationEntity
from app.services.webhook_service import WebhookService


class CriticalFindingsPayload(BaseModel):
    """Payload for triggering webhook dispatch on critical findings."""
    scan_id: str
    critical_findings: list


class WebhookRegistration(BaseModel):
    """Webhook registration request."""
    name: str
    endpoint_url: str
    secret: str
    events: list
    max_retries: int = 3
    backoff_base_seconds: float = 1.0
    timeout_seconds: int = 10
    is_active: bool = True


router = APIRouter(prefix="/webhooks", tags=["webhooks"])


@router.post(
    "",
    status_code=status.HTTP_201_CREATED,
    summary="Register a new webhook configuration",
)
def register_webhook(
    payload: WebhookRegistration,
    db: Session = Depends(get_db),
) -> dict:
    """Register a new webhook configuration in the database.

    Args:
        payload: Webhook registration details
        db: Database session

    Returns:
        Created webhook configuration
    """
    try:
        webhook = WebhookService.register_webhook(
            name=payload.name,
            endpoint_url=payload.endpoint_url,
            secret=payload.secret,
            events=payload.events,
            max_retries=payload.max_retries,
            backoff_base_seconds=payload.backoff_base_seconds,
            timeout_seconds=payload.timeout_seconds,
            is_active=payload.is_active,
        )
        db.close()
        return {
            "id": webhook.id,
            "name": webhook.name,
            "endpoint_url": webhook.endpoint_url,
            "events": webhook.events,
            "is_active": webhook.is_active,
        }
    except Exception as e:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Webhook registration failed: {str(e)}",
        )


@router.post(
    "/trigger-critical-findings",
    status_code=status.HTTP_202_ACCEPTED,
    summary="Trigger webhook dispatch for critical scan findings",
)
def trigger_critical_findings_webhook(
    payload: CriticalFindingsPayload,
    db: Session = Depends(get_db),
) -> dict:
    """Dispatch webhook notifications for critical tier findings from a scan.

    Sends outbound webhook endpoints with HMAC signature verification.
    Includes exponential backoff retry policy and audit tracking.

    Args:
        payload: The scan_id and critical_findings payload
        db: Database session

    Returns:
        Dispatch results summary
    """
    try:
        results = WebhookService.trigger_critical_findings_webhook(
            scan_id=payload.scan_id,
            critical_findings=payload.critical_findings,
            db_session=db,
        )
        db.close()
        return {
            "scan_id": payload.scan_id,
            "dispatch_results": [
                {
                    "webhook_id": r.webhook_id,
                    "success": r.success,
                    "status_code": r.status_code,
                    "error": r.error,
                }
                for r in results
            ],
        }
    except Exception as e:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Webhook dispatch failed: {str(e)}",
        )
