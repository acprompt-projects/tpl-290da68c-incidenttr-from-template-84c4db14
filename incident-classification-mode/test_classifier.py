from classifier import IncidentClassifier, Incident, ClassificationThresholds, Severity, Category


def test_p1_security_breach():
    clf = IncidentClassifier()
    incident = Incident(
        title="Security breach detected in production",
        description="Unauthorized access and compromised user data",
        tags={"category_hint": "security"},
    )
    label = clf.classify(incident)
    assert label.severity == Severity.P1
    assert label.category == Category.SECURITY
    assert label.escalation_required is True
    assert label.auto_acknowledge is False
    assert len(label.matched_rules) > 0


def test_p2_app_degraded():
    clf = IncidentClassifier()
    incident = Incident(
        title="API degraded performance",
        description="Error rate spike and high latency on /v2/orders",
        metric_name="error_rate",
    )
    label = clf.classify(incident)
    assert label.severity == Severity.P2
    assert label.category == Category.APP
    assert label.escalation_required is True


def test_p3_infra_warning():
    clf = IncidentClassifier()
    incident = Incident(
        title="CPU warning on node-03",
        description="Elevated rate of retries and slow_response observed",
        tags={"category_hint": "infra"},
    )
    label = clf.classify(incident)
    assert label.severity == Severity.P3
    assert label.category == Category.INFRA
    assert label.escalation_required is False


def test_p4_low_noise():
    clf = IncidentClassifier()
    incident = Incident(title="Routine check passed", description="All clear")
    label = clf.classify(incident)
    assert label.severity == Severity.P4
    assert label.auto_acknowledge is True


def test_network_category():
    clf = IncidentClassifier()
    incident = Incident(
        title="DNS resolution failures and packet_loss spike",
        description="Firewall blocking traffic on vpn tunnel",
    )
    label = clf.classify(incident)
    assert label.category == Category.NETWORK


def test_custom_thresholds():
    thresholds = ClassificationThresholds(critical_score=0.5, high_score=0.3, medium_score=0.15)
    clf = IncidentClassifier(thresholds)
    incident = Incident(title="Timeout on deploy", description="Retry and slow_response")
    label = clf.classify(incident)
    assert label.severity in (Severity.P1, Severity.P2, Severity.P3)


if __name__ == "__main__":
    test_p1_security_breach()
    test_p2_app_degraded()
    test_p3_infra_warning()
    test_p4_low_noise()
    test_network_category()
    test_custom_thresholds()
    print("All tests passed.")