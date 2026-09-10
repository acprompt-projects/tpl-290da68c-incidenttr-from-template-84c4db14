from __future__ import annotations
import enum
from datetime import datetime
from pydantic import BaseModel, Field


class Severity(str, enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class IncidentStatus(str, enum.Enum):
    OPEN = "open"
    TRIAGING = "triaging"
    ACKNOWLEDGED = "acknowledged"
    RESOLVED = "resolved"


class Alert(BaseModel):
    source: str = Field(..., description="Originating rules-engine rule id")
    fingerprint: str = Field(..., description="Dedup key for correlation")
    title: str
    description: str = ""
    labels: dict[str, str] = Field(default_factory=dict)
    raw_severity: Severity | None = None
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class TriageUpdate(BaseModel):
    severity: Severity | None = None
    status: IncidentStatus | None = None
    assignee: str | None = None
    notes: str | None = None


class Incident(BaseModel):
    id: str
    fingerprint: str
    title: str
    description: str
    source: str
    severity: Severity
    status: IncidentStatus
    labels: dict[str, str]
    assignee: str | None = None
    notes: str | None = None
    alert_count: int = 1
    created_at: datetime
    updated_at: datetime