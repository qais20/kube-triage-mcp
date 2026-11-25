from kube_triage_mcp.diagnose import diagnose_node, diagnose_pod, rank

from .fakes import CRASH, EVENTS, HEALTHY, OOM, PENDING, PULL, cs, event, pod


def reasons(p, events=()):
    return [f.reason for f in diagnose_pod(p, list(events))]


def test_healthy_pod_has_no_findings():
    assert diagnose_pod(HEALTHY) == []


def test_crashloop_points_at_previous_logs():
    [f] = diagnose_pod(CRASH)
    assert f.reason == "CrashLoop" and "exit 1" in f.summary and "previous=true" in f.next_step


def test_oomkilled_reports_memory_limit():
    [f] = diagnose_pod(OOM)
    assert f.reason == "OOMKilled" and "128Mi" in f.summary


def test_image_pull_missing_tag():
    [f] = diagnose_pod(PULL, EVENTS)
    assert f.reason == "ImagePull" and "tag does not exist" in f.summary


def test_image_pull_auth():
    ev = [event("web-88-pull", "Failed", "pull access denied, repository does not exist or may require authorization")]
    [f] = diagnose_pod(PULL, ev)
    assert "registry refused" in f.summary and "imagePullSecrets" in f.next_step


def test_unschedulable_insufficient_memory():
    [f] = diagnose_pod(PENDING)
    assert f.reason == "Unschedulable" and "Lower requests" in f.next_step


def test_liveness_probe_beats_generic_crashloop():
    ev = [event("api-7c9-crash", "Unhealthy", "Liveness probe failed: HTTP probe failed with statuscode: 500")]
    assert reasons(CRASH, ev) == ["LivenessProbe"]


def test_readiness_failure_is_warning():
    p = pod("api-x", statuses=[cs({"running": {}}, ready=False)])
    ev = [event("api-x", "Unhealthy", "Readiness probe failed: connection refused")]
    [f] = diagnose_pod(p, ev)
    assert f.reason == "NotReady" and f.severity == "warning"


def test_missing_secret():
    p = pod(
        "api-y",
        statuses=[cs({"waiting": {"reason": "CreateContainerConfigError", "message": 'secret "db-creds" not found'}})],
    )
    [f] = diagnose_pod(p)
    assert f.reason == "ConfigError" and "db-creds" in f.summary


def test_flapping():
    p = pod("api-z", statuses=[cs({"running": {}}, {"reason": "Error", "exitCode": 1}, restarts=9, ready=True)])
    assert reasons(p) == ["Flapping"]


def test_evicted():
    p = pod("old", phase="Failed", reason="Evicted", message="The node was low on resource: memory.")
    assert reasons(p) == ["Evicted"]


def test_node_not_ready():
    n = {"metadata": {"name": "node-b"}, "status": {"conditions": [{"type": "Ready", "status": "Unknown"}]}}
    assert diagnose_node(n).reason == "NodeNotReady"


def test_rank_puts_critical_first():
    p = pod("api-z", statuses=[cs({"running": {}}, None, restarts=9, ready=True)])
    found = rank(diagnose_pod(p) + diagnose_pod(CRASH))
    assert [f.severity for f in found] == ["critical", "warning"]


def test_crash_caught_between_restarts():
    p = pod("api-b", statuses=[cs({"terminated": {"reason": "Error", "exitCode": 1}}, restarts=3)])
    assert reasons(p) == ["CrashLoop"]
