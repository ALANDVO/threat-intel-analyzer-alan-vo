"""Webhook service for automated security alert dispatch with HMAC signature verification."""
import hashlib
import hmac
import json
import time
from typing import Dict, List, Any, Optional
from datetime import datetime, timezone

from app.models.entities import WebhookConfigurationEntity, AuditLogEntity


def _compute_hmac_signature(payload: Dict[str, Any], secret: str) -> str:
    """Compute HMAC-SHA256 signature for webhook payload."""
    payload_bytes = json.dumps(payload, sort_keys=True, default=str).encode('utf-8')
    mac = hmac.new(secret.encode('utf-8'), payload_bytes, hashlib.sha256)
    return mac.hexdigest()


def verify_webhook_signature(payload: Dict[str, Any], signature: str, secret: str) -> bool:
    """Verify webhook HMAC signature. Returns True if valid."""
    if not signature or not signature.startswith('sha256='):
        return False
    expected_sig = signature[len('sha256='):]
    computed = _compute_hmac_signature(payload, secret)
    return hmac.compare_digest(expected_sig, computed)


class WebhookDispatchResult:
    """Result of a webhook dispatch attempt."""
    def __init__(self, webhook_id: str, success: bool, status_code: Optional[int] = None,
                 response_body: Optional[str] = None, error: Optional[str] = None,
                 dispatched_at: Optional[datetime] = None):
        self.webhook_id = webhook_id
        self.success = success
        self.status_code = status_code
        self.response_body = response_body
        self.error = error
        self.dispatched_at = dispatched_at or datetime.now(timezone.utc)


class WebhookService:
    """Service for managing webhook configurations and dispatching events."""

    DEFAULT_MAX_RETRIES = 3
    DEFAULT_BACKOFF_BASE_SECONDS = 1.0
    DEFAULT_TIMEOUT_SECONDS = 10

    @staticmethod
    def register_webhook(
        name: str,
        endpoint_url: str,
        secret: str,
        events: List[str],
        max_retries: int = DEFAULT_MAX_RETRIES,
        backoff_base_seconds: float = DEFAULT_BACKOFF_BASE_SECONDS,
        timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
        is_active: bool = True,
    ) -> WebhookConfigurationEntity:
        """Register a new webhook configuration in the database."""
        from app.core.database import SessionLocal

        db = SessionLocal()
        try:
            # Check for duplicate name
            existing = db.query(WebhookConfigurationEntity).filter(
                WebhookConfigurationEntity.name == name,
                WebhookConfigurationEntity.is_active == True,
            ).first()
            if existing:
                raise ValueError(f"Webhook '{name}' already registered.")

            config = WebhookConfigurationEntity(
                name=name,
                endpoint_url=endpoint_url,
                hmac_secret=secret,
                events=list(events),
                max_retries=max_retries,
                backoff_base_seconds=backoff_base_seconds,
                timeout_seconds=timeout_seconds,
                is_active=is_active,
            )
            db.add(config)
            db.commit()
            db.refresh(config)
            return config
        finally:
            db.close()

    @staticmethod
    def list_webhooks() -> List[WebhookConfigurationEntity]:
        """List all webhook configurations."""
        from app.core.database import SessionLocal

        db = SessionLocal()
        try:
            return db.query(WebhookConfigurationEntity).all()
        finally:
            db.close()

    @staticmethod
    def update_webhook(
        webhook_id: str,
        endpoint_url: Optional[str] = None,
        secret: Optional[str] = None,
        events: Optional[List[str]] = None,
        max_retries: Optional[int] = None,
        backoff_base_seconds: Optional[float] = None,
        timeout_seconds: Optional[int] = None,
        is_active: Optional[bool] = None,
    ) -> WebhookConfigurationEntity:
        """Update an existing webhook configuration."""
        from app.core.database import SessionLocal
        from sqlalchemy.orm import Session
        from app.models.entities import WebhookConfigurationEntity

        db = SessionLocal()
        try:
            config = db.query(WebhookConfigurationEntity).filter(
                WebhookConfigurationEntity.id == webhook_id
            ).first()
            if not config:
                raise ValueError(f"Webhook '{webhook_id}' not found.")

            if endpoint_url is not None:
                config.endpoint_url = endpoint_url
            if secret is not None:
                config.hmac_secret = secret
            if events is not None:
                config.events = list(events)
            if max_retries is not None:
                config.max_retries = max_retries
            if backoff_base_seconds is not None:
                config.backoff_base_seconds = backoff_base_seconds
            if timeout_seconds is not None:
                config.timeout_seconds = timeout_seconds
            if is_active is not None:
                config.is_active = is_active

            db.commit()
            db.refresh(config)
            return config
        finally:
            db.close()

    @staticmethod
    def delete_webhook(webhook_id: str) -> bool:
        """Soft-delete a webhook (set inactive)."""
        from app.core.database import SessionLocal
        from app.models.entities import WebhookConfigurationEntity

        db = SessionLocal()
        try:
            config = db.query(WebhookConfigurationEntity).filter(
                WebhookConfigurationEntity.id == webhook_id
            ).first()
            if not config:
                return False
            config.is_active = False
            db.commit()
            return True
        finally:
            db.close()

    @classmethod
    def _build_backoff_delay(
        cls, attempt: int, base_seconds: float = DEFAULT_BACKOFF_BASE_SECONDS
    ) -> float:
        """Calculate exponential backoff delay for retry attempt."""
        return min(base_seconds * (2 ** (attempt - 1)), 60.0)

    @classmethod
    def dispatch_event(
        cls,
        event_type: str,
        payload: Dict[str, Any],
        webhook_id: str,
        db_session=None,
    ) -> List[WebhookDispatchResult]:
        """Dispatch an event to all matching webhook configurations.

        Retries with exponential backoff. Returns dispatch results per webhook.
        """
        from app.core.database import SessionLocal
        from sqlalchemy.orm import Session

        results: List[WebhookDispatchResult] = []

        if db_session is None:
            db_session = SessionLocal()

        try:
            # Fetch active webhooks matching the event type
            webhooks = db_session.query(WebhookConfigurationEntity).filter(
                WebhookConfigurationEntity.is_active == True,
                WebhookConfigurationEntity.events.contains([event_type]),
            ).all()

            for webhook in webhooks:
                result = cls._dispatch_to_webhook(
                    webhook, event_type, payload, db_session
                )
                results.append(result)

            db_session.commit()
        except Exception as e:
            db_session.rollback()
            raise
        finally:
            if db_session is not None and db_session.bind:
                db_session.close()

        return results

    @classmethod
    def _dispatch_to_webhook(
        cls,
        webhook: WebhookConfigurationEntity,
        event_type: str,
        payload: Dict[str, Any],
        db_session: Any,
    ) -> WebhookDispatchResult:
        """Dispatch a single webhook with HMAC signature and retry logic."""
        import httpx
        from sqlalchemy.orm import Session as SA_Session

        secret = webhook.hmac_secret or ""
        url = webhook.endpoint_url
        max_retries = webhook.max_retries or cls.DEFAULT_MAX_RETRIES
        backoff_base = webhook.backoff_base_seconds or cls.DEFAULT_BACKOFF_BASE_SECONDS
        timeout = webhook.timeout_seconds or cls.DEFAULT_TIMEOUT_SECONDS

        # Prepare payload with event metadata
        dispatch_payload = {
            "event_type": event_type,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "payload": payload,
        }

        # Compute HMAC signature
        signature = _compute_hmac_signature(dispatch_payload, secret)
        headers = {
            "Content-Type": "application/json",
            "X-Webhook-Signature": f"sha256={signature}",
            "X-Webhook-Event": event_type,
        }

        last_error: Optional[str] = None

        for attempt in range(1, max_retries + 1):
            backoff = cls._build_backoff_delay(attempt, backoff_base)
            if attempt > 1:
                time.sleep(backoff)

            try:
                response = httpx.post(
                    url,
                    json=dispatch_payload,
                    headers=headers,
                    timeout=timeout,
                )

                # Attempt to log audit entry
                from app.models.entities import AuditLogEntity
                audit_entry = AuditLogEntity(
                    actor_id=None,
                    actor_email='system@threat-intel.local',
                    actor_role='system',
                    action='webhook.dispatch',
                    resource_type='webhook',
                    resource_id=webhook.id,
                    details={
                        "event_type": event_type,
                        "webhook_id": webhook.id,
                        "status_code": response.status_code,
                        "attempt": attempt,
                    },
                    ip_address=None,
                )
                db_session.add(audit_entry)
                db_session.commit()

                return WebhookDispatchResult(
                    webhook_id=webhook.id,
                    success=True,
                    status_code=response.status_code,
                    response_body=response.text[:500] if response.text else None,
                )
            except httpx.HTTPError as e:
                last_error = str(e)
                # Log retry attempt audit
                from app.models.entities import AuditLogEntity
                audit_attempt = AuditLogEntity(
                    actor_id=None,
                    actor_email='system@threat-intel.local',
                    actor_role='system',
                    action='webhook.dispatch.attempt',
                    resource_type='webhook',
                    resource_id=webhook.id,
                    details={
                        "event_type": event_type,
                        "webhook_id": webhook.id,
                        "attempt": attempt,
                        "error": last_error,
                    },
                    ip_address=None,
                )
                db_session.add(audit_attempt)
                db_session.commit()
            except Exception as e:
                last_error = f"Unexpected error: {str(e)}"
                from app.models.entities import AuditLogEntity
                audit_attempt = AuditLogEntity(
                    actor_id=None,
                    actor_email='system@threat-intel.local',
                    actor_role='system',
                    action='webhook.dispatch.attempt',
                    resource_type='webhook',
                    resource_id=webhook.id,
                    details={
                        "event_type": event_type,
                        "webhook_id": webhook.id,
                        "attempt": attempt,
                        "error": last_error,
                    },
                    ip_address=None,
                )
                db_session.add(audit_attempt)
                db_session.commit()

        # All retries exhausted
        from app.models.entities import AuditLogEntity
        audit_final = AuditLogEntity(
            actor_id=None,
            actor_email='system@threat-intel.local',
            actor_role='system',
            action='webhook.dispatch.failed',
            resource_type='webhook',
            resource_id=webhook.id,
            details={
                "event_type": event_type,
                "webhook_id": webhook.id,
                "max_retries": max_retries,
                "final_error": last_error,
            },
            ip_address=None,
        )
        db_session.add(audit_final)
        db_session.commit()

        return WebhookDispatchResult(
            webhook_id=webhook.id,
            success=False,
            error=last_error,
        )

    @classmethod
    def trigger_critical_findings_webhook(
        cls,
        scan_id: str,
        critical_findings: List[Dict[str, Any]],
        db_session=None,
    ) -> List[WebhookDispatchResult]:
        """Trigger webhook dispatch for critical findings from a scan.

        This is the convenience method called when scans detect critical tier findings.
        """
        from app.models.entities import ThreatScanEntity

        payload = {
            "scan_id": scan_id,
            "findings": critical_findings,
            "finding_count": len(critical_findings),
            "event": "critical_findings",
        }

        if db_session is None:
            from app.core.database import SessionLocal
            db_session = SessionLocal()

        try:
            results = cls.dispatch_event("critical_findings", payload, scan_id, db_session)
            return results
        finally:
            if db_session is not None and db_session.bind:
                db_session.close()
