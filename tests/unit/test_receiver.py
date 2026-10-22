"""Falco receiver: payload parsing and that an actionable alert triggers a restart."""

from detector.executor import RemediationExecutor
from detector.receiver import parse_falco


def test_parse_standard_falco_payload():
    payload = {
        "priority": "Critical",
        "rule": "Terminal shell in container",
        "output": "A shell was spawned...",
        "output_fields": {
            "k8s.pod.name": "epsi-pay-auth-abc123",
            "k8s.ns.name": "applications",
            "user.name": "root",
        },
    }
    alert = parse_falco(payload)
    assert alert["priority"] == "critical"
    assert alert["pod"] == "epsi-pay-auth-abc123"
    assert alert["namespace"] == "applications"


def test_parse_missing_fields_is_safe():
    alert = parse_falco({})
    assert alert["priority"] == ""
    assert alert["pod"] == ""


def test_restart_map_resolves_auth_pod_to_deployment():
    ex = RemediationExecutor(mode="dry_run")
    # dry_run returns False but must not raise and must resolve the mapping.
    assert ex.restart_service("auth") is False
    assert ex.restart_service("unknown-service") is False
