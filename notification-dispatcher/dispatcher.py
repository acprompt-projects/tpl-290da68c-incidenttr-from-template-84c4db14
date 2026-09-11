from __future__ import annotations
import time
import smtplib
import logging
from email.mime.text import MIMEText
from typing import Any, Dict, List, Optional
import httpx

from config import Channel, NotificationSettings, Severity, DEFAULT_SETTINGS

logger = logging.getLogger(__name__)


class RateLimiter:
    """Sliding-window rate limiter."""

    def __init__(self, max_calls: int = 10, window_seconds: int = 60):
        self.max_calls = max_calls
        self.window_seconds = window_seconds
        self._timestamps: List[float] = []

    def allow(self) -> bool:
        now = time.monotonic()
        cutoff = now - self.window_seconds
        self._timestamps = [t for t in self._timestamps if t > cutoff]
        if len(self._timestamps) >= self.max_calls:
            return False
        self._timestamps.append(now)
        return True


class IncidentPayload:
    """Normalized incident data passed to the dispatcher."""

    def __init__(
        self,
        incident_id: str,
        title: str,
        severity: Severity,
        category: str,
        description: str = "",
        metadata: Optional[Dict[str, Any]] = None,
    ):
        self.incident_id = incident_id
        self.title = title
        self.severity = severity
        self.category = category
        self.description = description
        self.metadata = metadata or {}


class NotificationDispatcher:
    """Routes triaged incidents to the correct notification channels."""

    def __init__(self, settings: Optional[NotificationSettings] = None):
        self.settings = settings or DEFAULT_SETTINGS
        self._limiters: Dict[str, RateLimiter] = {}
        for name, cfg in self.settings.rate_limits.items():
            self._limiters[name] = RateLimiter(cfg.max_calls, cfg.window_seconds)
        self._http = httpx.AsyncClient(timeout=10.0)

    def _get_limiter(self, channel: Channel) -> Optional[RateLimiter]:
        return self._limiters.get(channel.value)

    async def dispatch(self, incident: IncidentPayload) -> Dict[str, bool]:
        channels = self.settings.resolve_channels(incident.severity, incident.category)
        results: Dict[str, bool] = {}
        for ch in channels:
            limiter = self._get_limiter(ch)
            if limiter and not limiter.allow():
                logger.warning("Rate limited channel %s for incident %s", ch.value, incident.incident_id)
                results[ch.value] = False
                continue
            try:
                if ch == Channel.SLACK:
                    ok = await self._send_slack(incident)
                elif ch == Channel.PAGERDUTY:
                    ok = await self._send_pagerduty(incident)
                elif ch == Channel.EMAIL:
                    ok = await self._send_email(incident)
                else:
                    logger.error("Unknown channel: %s", ch)
                    ok = False
                results[ch.value] = ok
            except Exception as exc:
                logger.exception("Failed to send via %s: %s", ch.value, exc)
                results[ch.value] = False
        return results

    async def _send_slack(self, incident: IncidentPayload) -> bool:
        cfg = self.settings.slack
        if not cfg:
            logger.warning("Slack not configured; skipping")
            return False
        color = {"critical": "#ff0000", "high": "#ff6600",
                 "medium": "#ffcc00", "low": "#3399ff", "info": "#999999"}
        payload = {
            "username": cfg.username,
            "icon_emoji": cfg.icon_emoji,
            "attachments": [{
                "color": color.get(incident.severity.value, "#999999"),
                "title": f"[{incident.severity.value.upper()}] {incident.title}",
                "text": incident.description,
                "fields": [
                    {"title": "Incident ID", "value": incident.incident_id, "short": True},
                    {"title": "Category", "value": incident.category, "short": True},
                ],
                "footer": "incident-triage",
            }],
        }
        resp = await self._http.post(cfg.webhook_url, json=payload)
        return resp.status_code == 200

    async def _send_pagerduty(self, incident: IncidentPayload) -> bool:
        cfg = self.settings.pagerduty
        if not cfg:
            logger.warning("PagerDuty not configured; skipping")
            return False
        severity = cfg.severity_map.get(incident.severity.value, "info")
        payload = {
            "routing_key": cfg.routing_key,
            "event_action": "trigger",
            "payload": {
                "summary": f"[{incident.severity.value.upper()}] {incident.title}",
                "severity": severity,
                "source": incident.metadata.get("source", "incident-triage"),
                "component": incident.category,
                "group": incident.metadata.get("group", ""),
                "class": incident.category,
                "custom_details": {
                    "incident_id": incident.incident_id,
                    "description": incident.description,
                },
            },
        }
        resp = await self._http.post(cfg.api_url, json=payload)
        return resp.status_code in (200, 202)

    async def _send_email(self, incident: IncidentPayload) -> bool:
        cfg = self.settings.email
        if not cfg or not cfg.recipients:
            logger.warning("Email not configured or no recipients; skipping")
            return False
        subject = f"[{incident.severity.value.upper()}] {incident.title} ({incident.incident_id})"
        body = (
            f"Incident ID: {incident.incident_id}\n"
            f"Title: {incident.title}\n"
            f"Severity: {incident.severity.value}\n"
            f"Category: {incident.category}\n\n"
            f"{incident.description}\n"
        )
        msg = MIMEText(body)
        msg["Subject"] = subject
        msg["From"] = cfg.sender
        msg["To"] = ", ".join(cfg.recipients)
        try:
            with smtplib.SMTP(cfg.smtp_host, cfg.smtp_port) as smtp:
                if cfg.use_tls:
                    smtp.starttls()
                smtp.send_message(msg)
            return True
        except smtplib.SMTPException as exc:
            logger.error("SMTP error: %s", exc)
            return False

    async def close(self) -> None:
        await self._http.aclose()