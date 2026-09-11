from __future__ import annotations
from enum import Enum
from typing import Dict, List, Optional
from pydantic import BaseModel, Field


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Channel(str, Enum):
    SLACK = "slack"
    PAGERDUTY = "pagerduty"
    EMAIL = "email"


class RoutingRule(BaseModel):
    severities: List[Severity] = Field(default_factory=lambda: list(Severity))
    categories: List[str] = Field(default_factory=lambda: ["*"])
    channels: List[Channel]


class SlackConfig(BaseModel):
    webhook_url: str
    username: str = "IncidentBot"
    icon_emoji: str = ":rotating_light:"


class PagerDutyConfig(BaseModel):
    routing_key: str
    api_url: str = "https://events.pagerduty.com/v2/enqueue"
    severity_map: Dict[str, str] = Field(default_factory=lambda: {
        "critical": "critical", "high": "high",
        "medium": "warning", "low": "low", "info": "info",
    })


class EmailConfig(BaseModel):
    smtp_host: str = "localhost"
    smtp_port: int = 587
    sender: str = "incidents@example.com"
    recipients: List[str] = Field(default_factory=list)
    use_tls: bool = True


class RateLimitConfig(BaseModel):
    max_calls: int = 10
    window_seconds: int = 60


class NotificationSettings(BaseModel):
    routing_rules: List[RoutingRule] = Field(default_factory=list)
    slack: Optional[SlackConfig] = None
    pagerduty: Optional[PagerDutyConfig] = None
    email: Optional[EmailConfig] = None
    rate_limits: Dict[str, RateLimitConfig] = Field(default_factory=dict)
    default_channels: List[Channel] = Field(default_factory=lambda: [Channel.SLACK])

    def resolve_channels(self, severity: Severity, category: str) -> List[Channel]:
        matched: List[Channel] = []
        for rule in self.routing_rules:
            sev_ok = severity in rule.severities
            cat_ok = "*" in rule.categories or category in rule.categories
            if sev_ok and cat_ok:
                matched.extend(rule.channels)
        return list(dict.fromkeys(matched)) or self.default_channels


DEFAULT_SETTINGS = NotificationSettings(
    routing_rules=[
        RoutingRule(
            severities=[Severity.CRITICAL],
            categories=["*"],
            channels=[Channel.SLACK, Channel.PAGERDUTY, Channel.EMAIL],
        ),
        RoutingRule(
            severities=[Severity.HIGH],
            categories=["*"],
            channels=[Channel.SLACK, Channel.PAGERDUTY],
        ),
        RoutingRule(
            severities=[Severity.MEDIUM],
            categories=["security", "infrastructure"],
            channels=[Channel.SLACK, Channel.EMAIL],
        ),
        RoutingRule(
            severities=[Severity.MEDIUM],
            categories=["*"],
            channels=[Channel.SLACK],
        ),
        RoutingRule(
            severities=[Severity.LOW, Severity.INFO],
            categories=["*"],
            channels=[Channel.SLACK],
        ),
    ],
    rate_limits={
        "slack": RateLimitConfig(max_calls=20, window_seconds=60),
        "pagerduty": RateLimitConfig(max_calls=10, window_seconds=60),
        "email": RateLimitConfig(max_calls=30, window_seconds=60),
    },
)