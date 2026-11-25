"""Hand-built pod/event fixtures shaped like real API responses."""

from __future__ import annotations

from typing import Any


def pod(
    name: str,
    ns: str = "shop",
    phase: str = "Running",
    statuses: list | None = None,
    conditions: list | None = None,
    limits: dict | None = None,
    image: str = "shop/api:1.4.2",
    **status: Any,
) -> dict[str, Any]:
    return {
        "metadata": {
            "name": name,
            "namespace": ns,
            "ownerReferences": [{"kind": "ReplicaSet", "name": f"{name.rsplit('-', 2)[0]}-6d4f"}],
        },
        "spec": {
            "nodeName": "node-a",
            "containers": [{"name": "app", "image": image, "resources": {"limits": limits or {}}}],
        },
        "status": {"phase": phase, "containerStatuses": statuses or [], "conditions": conditions or [], **status},
    }


def cs(state: dict, last: dict | None = None, restarts: int = 0, ready: bool = False, name: str = "app"):
    return {
        "name": name,
        "image": "shop/api:1.4.2",
        "state": state,
        "ready": ready,
        "restartCount": restarts,
        "lastState": {"terminated": last} if last else {},
    }


def event(
    obj: str, reason: str, message: str, ns: str = "shop", type_: str = "Warning", ts: str = "2026-11-25T10:00:00Z"
):
    return {
        "type": type_,
        "reason": reason,
        "message": message,
        "count": 3,
        "lastTimestamp": ts,
        "involvedObject": {"kind": "Pod", "name": obj, "namespace": ns},
    }


CRASH = pod(
    "api-7c9-crash",
    statuses=[cs({"waiting": {"reason": "CrashLoopBackOff"}}, {"reason": "Error", "exitCode": 1}, restarts=7)],
)
OOM = pod(
    "worker-5b-oom",
    limits={"memory": "128Mi"},
    statuses=[cs({"waiting": {"reason": "CrashLoopBackOff"}}, {"reason": "OOMKilled", "exitCode": 137}, 4)],
)
PULL = pod(
    "web-88-pull",
    image="shop/web:does-not-exist",
    statuses=[cs({"waiting": {"reason": "ImagePullBackOff", "message": "Back-off pulling image"}})],
)
PENDING = pod(
    "batch-1-pending",
    phase="Pending",
    conditions=[
        {
            "type": "PodScheduled",
            "status": "False",
            "reason": "Unschedulable",
            "message": "0/3 nodes are available: 3 Insufficient memory.",
        }
    ],
)
HEALTHY = pod("api-7c9-ok", statuses=[cs({"running": {}}, ready=True)])
OTHER_NS = pod(
    "secret-thing",
    ns="payments",
    statuses=[cs({"waiting": {"reason": "CrashLoopBackOff"}}, {"reason": "Error", "exitCode": 2}, 3)],
)

EVENTS = [
    event("web-88-pull", "Failed", 'Failed to pull image "shop/web:does-not-exist": manifest unknown'),
    event("api-7c9-crash", "BackOff", "Back-off restarting failed container app"),
]


class FakeKube:
    def __init__(self, pods=None, events=None, nodes=None, logs="", deployment=None, replicasets=None):
        self.pods = pods if pods is not None else [CRASH, OOM, PULL, PENDING, HEALTHY, OTHER_NS]
        self.events = events if events is not None else EVENTS
        self.nodes = nodes or [
            {"metadata": {"name": "node-a"}, "status": {"conditions": [{"type": "Ready", "status": "True"}]}}
        ]
        self.logs = logs
        self.deployment = deployment or {
            "metadata": {"name": "api"},
            "spec": {"replicas": 3, "selector": {"matchLabels": {"app": "api"}}},
            "status": {"readyReplicas": 1},
        }
        self.replicasets = replicasets or []
        self.writes: list[tuple] = []

    def list_pods(self, namespace):
        return [p for p in self.pods if namespace in (None, p["metadata"]["namespace"])]

    def get_pod(self, namespace, name):
        for p in self.pods:
            if p["metadata"]["namespace"] == namespace and p["metadata"]["name"] == name:
                return p
        err = Exception("not found")
        err.status = 404  # type: ignore[attr-defined]
        raise err

    def list_nodes(self):
        return self.nodes

    def list_events(self, namespace, involved=None):
        return [
            e
            for e in self.events
            if namespace in (None, e["involvedObject"]["namespace"]) and involved in (None, e["involvedObject"]["name"])
        ]

    def pod_logs(self, namespace, name, container, previous, tail):
        return self.logs

    def get_deployment(self, namespace, name):
        return self.deployment

    def list_replicasets(self, namespace, selector):
        return self.replicasets

    def patch_deployment(self, namespace, name, body):
        self.writes.append(("patch", namespace, name, body))

    def scale_deployment(self, namespace, name, replicas):
        self.writes.append(("scale", namespace, name, replicas))
