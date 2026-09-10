from __future__ import annotations
import uuid
from datetime import datetime
from fastapi import FastAPI, HTTPException
from .models import Alert, Incident, IncidentStatus, Severity, TriageUpdate

app = FastAPI(title="Incident Triage Service", version="0.1.0")

_incidents: dict[str, Incident] = {}
_fingerprint_index: dict[str, str] = {}

_SEVERITY_ORDER = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]


def _classify_severity(alert: Alert) -> Severity:
    if alert.raw_severity:
        return alert.raw_severity
    labels = alert.labels
    if labels.get("env") == "production" and labels.get("oncall") == "true":
        return Severity.CRITICAL
    if labels.get("env") == "production":
        return Severity.HIGH
    if labels.get("env") == "staging":
        return Severity.MEDIUM
    return Severity.LOW


def _escalate(current: Severity, candidate: Severity) -> Severity:
    if _SEVERITY_ORDER.index(candidate) > _SEVERITY_ORDER.index(current):
        return candidate
    return current


@app.post("/incidents", response_model=Incident, status_code=201)
def create_incident(alert: Alert) -> Incident:
    now = datetime.utcnow()
    fp = alert.fingerprint
    if fp in _fingerprint_index:
        inc_id = _fingerprint_index[fp]
        inc = _incidents[inc_id]
        inc.alert_count += 1
        inc.severity = _escalate(inc.severity, _classify_severity(alert))
        inc.updated_at = now
        if alert.description and not inc.description:
            inc.description = alert.description
        return inc
    inc_id = str(uuid.uuid4())
    inc = Incident(
        id=inc_id, fingerprint=fp, title=alert.title,
        description=alert.description, source=alert.source,
        severity=_classify_severity(alert), status=IncidentStatus.OPEN,
        labels=alert.labels, created_at=now, updated_at=now,
    )
    _incidents[inc_id] = inc
    _fingerprint_index[fp] = inc_id
    return inc


@app.get("/incidents/{incident_id}", response_model=Incident)
def get_incident(incident_id: str) -> Incident:
    inc = _incidents.get(incident_id)
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")
    return inc


@app.patch("/incidents/{incident_id}/triage", response_model=Incident)
def update_triage(incident_id: str, update: TriageUpdate) -> Incident:
    inc = _incidents.get(incident_id)
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")
    if update.severity is not None:
        inc.severity = update.severity
    if update.status is not None:
        inc.status = update.status
    if update.assignee is not None:
        inc.assignee = update.assignee
    if update.notes is not None:
        inc.notes = update.notes
    inc.updated_at = datetime.utcnow()
    return inc