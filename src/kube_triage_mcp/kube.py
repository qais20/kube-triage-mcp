"""Thin wrapper over the Kubernetes client.

Returns plain dicts (the API's camelCase JSON) so the rest of the code, and the
tests, never touch client model classes. Tests swap this for a fake.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Protocol


class KubeAPI(Protocol):
    def list_pods(self, namespace: str | None) -> list[dict[str, Any]]: ...
    def get_pod(self, namespace: str, name: str) -> dict[str, Any]: ...
    def list_nodes(self) -> list[dict[str, Any]]: ...
    def list_events(self, namespace: str | None, involved: str | None = None) -> list[dict[str, Any]]: ...
    def pod_logs(self, namespace: str, name: str, container: str | None, previous: bool, tail: int) -> str: ...
    def get_deployment(self, namespace: str, name: str) -> dict[str, Any]: ...
    def list_replicasets(self, namespace: str, selector: str) -> list[dict[str, Any]]: ...
    def patch_deployment(self, namespace: str, name: str, body: dict[str, Any]) -> None: ...
    def scale_deployment(self, namespace: str, name: str, replicas: int) -> None: ...


class LiveKube:
    def __init__(self, context: str | None = None) -> None:
        from kubernetes import client, config

        try:
            config.load_incluster_config()
        except config.ConfigException:
            config.load_kube_config(context=context)
        self._api = client.ApiClient()
        self.core = client.CoreV1Api(self._api)
        self.apps = client.AppsV1Api(self._api)

    def _d(self, obj: Any) -> Any:
        return self._api.sanitize_for_serialization(obj)

    def list_pods(self, namespace):
        r = self.core.list_namespaced_pod(namespace) if namespace else self.core.list_pod_for_all_namespaces()
        return self._d(r)["items"]

    def get_pod(self, namespace, name):
        return self._d(self.core.read_namespaced_pod(name, namespace))

    def list_nodes(self):
        return self._d(self.core.list_node())["items"]

    def list_events(self, namespace, involved=None):
        kw = {"field_selector": f"involvedObject.name={involved}"} if involved else {}
        if namespace:
            r = self.core.list_namespaced_event(namespace, **kw)
        else:
            r = self.core.list_event_for_all_namespaces(**kw)
        return self._d(r)["items"]

    def pod_logs(self, namespace, name, container, previous, tail):
        kw: dict[str, Any] = {"tail_lines": tail, "previous": previous}
        if container:
            kw["container"] = container
        return self.core.read_namespaced_pod_log(name, namespace, **kw)

    def get_deployment(self, namespace, name):
        return self._d(self.apps.read_namespaced_deployment(name, namespace))

    def list_replicasets(self, namespace, selector):
        return self._d(self.apps.list_namespaced_replica_set(namespace, label_selector=selector))["items"]

    def patch_deployment(self, namespace, name, body):
        self.apps.patch_namespaced_deployment(name, namespace, body)

    def scale_deployment(self, namespace, name, replicas):
        self.apps.patch_namespaced_deployment_scale(name, namespace, {"spec": {"replicas": replicas}})


def restart_patch() -> dict[str, Any]:
    """Same patch `kubectl rollout restart` sends."""
    now = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    return {"spec": {"template": {"metadata": {"annotations": {"kubectl.kubernetes.io/restartedAt": now}}}}}
