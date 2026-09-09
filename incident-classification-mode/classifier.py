import re
from enum import Enum
from dataclasses import dataclass, field
from typing import Optional


class Severity(str, Enum):
    P1 = "P1"
    P2 = "P2"
    P3 = "P3"
    P4 = "P4"


class Category(str, Enum):
    INFRA = "infra"
    APP = "app"
    SECURITY = "security"
    NETWORK = "network"


@dataclass
class ClassificationThresholds:
    critical_keywords: list[str] = field(default_factory=lambda: [
        "outage", "down", "unavailable", "data_loss", "breach", "compromised",
        "ransomware", "heartbeat_missing", "cluster_failure",
    ])
    high_keywords: list[str] = field(default_factory=lambda: [
        "degraded", "timeout", "error_rate_spike", "high_latency",
        "disk_full", "oom", "replication_lag",
    ])
    medium_keywords: list[str] = field(default_factory=lambda: [
        "warning", "retry", "slow_response", "elevated_rate",
        "patch_available", "cert_expiring",
    ])
    critical_score: float = 0.85
    high_score: float = 0.60
    medium_score: float = 0.30
    category_keywords: dict[str, list[str]] = field(default_factory=lambda: {
        "infra": ["cpu", "memory", "disk", "host", "vm", "container", "pod",
                   "node", "cluster", "instance", "heartbeat", "oom", "disk_full"],
        "app": ["error_rate", "latency", "response_time", "deploy", "rollback",
                "exception", "crash", "500", "503", "timeout", "degraded"],
        "security": ["breach", "compromised", "ransomware", "auth", "unauthorized",
                     "vuln", "cve", "intrusion", "malware", "phishing", "cert"],
        "network": ["dns", "connection", "packet_loss", "latency_spike", "route",
                    "firewall", "load_balancer", "bandwidth", "tcp", "ssl", "vpn"],
    })


@dataclass
class TriageLabel:
    severity: Severity
    category: Category
    confidence: float
    matched_rules: list[str]
    escalation_required: bool
    auto_acknowledge: bool


@dataclass
class Incident:
    title: str
    description: str = ""
    source: str = ""
    metric_name: str = ""
    metric_value: float = 0.0
    tags: dict[str, str] = field(default_factory=dict)


class IncidentClassifier:
    def __init__(self, thresholds: Optional[ClassificationThresholds] = None):
        self.thresholds = thresholds or ClassificationThresholds()
        self._compiled_patterns: dict[str, re.Pattern] = {}
        self._compile_patterns()

    def _compile_patterns(self):
        for cat, keywords in self.thresholds.category_keywords.items():
            joined = "|".join(map(re.escape, keywords))
            self._compiled_patterns[cat] = re.compile(
                rf"\b({joined})\b", re.IGNORECASE
            )

    def _compute_severity_score(self, incident: Incident) -> tuple[float, list[str]]:
        text = f"{incident.title} {incident.description} {incident.metric_name}"
        text_lower = text.lower()
        score = 0.0
        matched: list[str] = []

        for kw in self.thresholds.critical_keywords:
            if kw in text_lower:
                score += 0.35
                matched.append(f"critical:{kw}")

        for kw in self.thresholds.high_keywords:
            if kw in text_lower:
                score += 0.20
                matched.append(f"high:{kw}")

        for kw in self.thresholds.medium_keywords:
            if kw in text_lower:
                score += 0.10
                matched.append(f"medium:{kw}")

        tag_sev = incident.tags.get("severity_hint", "").lower()
        if tag_sev == "critical":
            score += 0.40
            matched.append("tag:critical")
        elif tag_sev == "high":
            score += 0.25
            matched.append("tag:high")

        return min(score, 1.0), matched

    def _map_severity(self, score: float) -> Severity:
        if score >= self.thresholds.critical_score:
            return Severity.P1
        if score >= self.thresholds.high_score:
            return Severity.P2
        if score >= self.thresholds.medium_score:
            return Severity.P3
        return Severity.P4

    def _determine_category(self, incident: Incident) -> tuple[Category, list[str]]:
        text = f"{incident.title} {incident.description} {incident.metric_name}"
        scores: dict[str, float] = {}
        matched_rules: list[str] = []

        for cat, pattern in self._compiled_patterns.items():
            hits = pattern.findall(text)
            if hits:
                scores[cat] = len(hits)
                matched_rules.append(f"cat:{cat}:{','.join(hits[:3])}")

        tag_cat = incident.tags.get("category_hint", "").lower()
        if tag_cat in {c.value for c in Category}:
            scores[tag_cat] = scores.get(tag_cat, 0) + 2.0
            matched_rules.append(f"tag_cat:{tag_cat}")

        if not scores:
            return Category.APP, ["cat:default:app"]

        best = max(scores, key=scores.get)
        return Category(best), matched_rules

    def classify(self, incident: Incident) -> TriageLabel:
        sev_score, sev_rules = self._compute_severity_score(incident)
        severity = self._map_severity(sev_score)
        category, cat_rules = self._determine_category(incident)

        all_rules = sev_rules + cat_rules
        confidence = round(sev_score if sev_score > 0 else 0.1, 3)

        escalation_required = severity in (Severity.P1, Severity.P2)
        auto_acknowledge = severity == Severity.P4

        return TriageLabel(
            severity=severity,
            category=category,
            confidence=confidence,
            matched_rules=all_rules,
            escalation_required=escalation_required,
            auto_acknowledge=auto_acknowledge,
        )