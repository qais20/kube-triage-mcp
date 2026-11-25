"""Turn raw pod state into findings a human (or a model) can act on.

Everything here is a pure function over plain dicts, the camelCase shape the
Kubernetes API returns. No cluster needed, so every rule is unit tested.
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from typing import Any

CRITICAL = "critical"
WARNING = "warning"

FLAPPING_RESTARTS = 5


@dataclass
class Finding:
    severity: str
    namespace: str
    pod: str
    reason: str
    summary: str
    next_step: str
    container: str | None = None
    evidence: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        seen: list[str] = []
        for e in d["evidence"]:
            e = e if len(e) <= 240 else e[:237] + "..."
            if e and not any(e[:60] in s for s in seen):
                seen.append(e)
        d["evidence"] = seen
        return {k: v for k, v in d.items() if v not in (None, [])}


def _events_text(events: list[dict[str, Any]]) -> list[str]:
    return [f"{e.get('reason', '')}: {e.get('message', '')}".strip() for e in events]


def _match_event(events: list[dict[str, Any]], pattern: str) -> str | None:
    rx = re.compile(pattern, re.IGNORECASE)
    for line in _events_text(events):
        if rx.search(line):
            return line
    return None


def _limit(pod: dict[str, Any], container: str, kind: str) -> str | None:
    for c in pod.get("spec", {}).get("containers", []):
        if c.get("name") == container:
            return ((c.get("resources") or {}).get("limits") or {}).get(kind)
    return None


def _image(pod: dict[str, Any], container: str) -> str | None:
    for c in pod.get("spec", {}).get("containers", []):
        if c.get("name") == container:
            return c.get("image")
    return None


def _container_findings(pod: dict[str, Any], cs: dict[str, Any], events: list[dict[str, Any]]) -> list[Finding]:
    meta = pod.get("metadata", {})
    ns, name, cname = meta.get("namespace", ""), meta.get("name", ""), cs.get("name", "")
    state = cs.get("state") or {}
    last = (cs.get("lastState") or {}).get("terminated") or {}
    waiting = state.get("waiting") or {}
    restarts = cs.get("restartCount", 0)
    base = {"namespace": ns, "pod": name, "container": cname}

    w_reason = waiting.get("reason", "")

    if w_reason in ("ImagePullBackOff", "ErrImagePull", "InvalidImageName"):
        image = _image(pod, cname) or "?"
        ev = _match_event(events, r"not found|manifest unknown|unauthorized|denied|no basic auth|pull access")
        if ev and re.search(r"unauthorized|denied|no basic auth|pull access", ev, re.I):
            cause, step = "registry refused the pull", "Check imagePullSecrets and the registry's access policy."
        elif ev and re.search(r"not found|manifest unknown", ev, re.I):
            cause, step = "tag does not exist", "Check the tag was pushed; compare with the last good revision."
        else:
            cause, step = "image could not be pulled", "Check the image reference and registry reachability."
        return [
            Finding(
                CRITICAL,
                reason="ImagePull",
                summary=f"Can't pull {image}: {cause}.",
                next_step=step,
                evidence=[e for e in [waiting.get("message"), ev] if e],
                **base,
            )
        ]

    if w_reason == "CreateContainerConfigError":
        msg = waiting.get("message", "")
        return [
            Finding(
                CRITICAL,
                reason="ConfigError",
                summary=f"Container can't be created: {msg or 'bad config'}.",
                next_step="A referenced Secret/ConfigMap or key is missing. Create it or fix the reference.",
                evidence=[msg] if msg else [],
                **base,
            )
        ]

    if last.get("reason") == "OOMKilled" or (state.get("terminated") or {}).get("reason") == "OOMKilled":
        limit = _limit(pod, cname, "memory")
        lim = f" (limit {limit})" if limit else " (no memory limit set)"
        return [
            Finding(
                CRITICAL,
                reason="OOMKilled",
                summary=f"Killed for running out of memory{lim}, {restarts} restarts.",
                next_step="Raise the memory limit or find the leak; check the memory graph before the kill.",
                evidence=[f"lastState.terminated.reason=OOMKilled exitCode={last.get('exitCode', 137)}"],
                **base,
            )
        ]

    term = state.get("terminated") or {}
    between_restarts = term and term.get("reason") != "Completed" and restarts > 0
    if w_reason == "CrashLoopBackOff" or between_restarts:
        last = last or term
        code = last.get("exitCode")
        probe = _match_event(events, r"liveness probe failed")
        if probe:
            return [
                Finding(
                    CRITICAL,
                    reason="LivenessProbe",
                    summary=f"Kubelet keeps killing it: liveness probe failing ({restarts} restarts).",
                    next_step="Probe is too strict or the app is too slow to start. Check path, port, "
                    "initialDelaySeconds; consider a startupProbe.",
                    evidence=[probe],
                    **base,
                )
            ]
        return [
            Finding(
                CRITICAL,
                reason="CrashLoop",
                summary=f"Crashes on start (exit {code if code is not None else '?'}), {restarts} restarts.",
                next_step="Read the previous container's logs: get_logs(previous=true).",
                evidence=[f"lastState.terminated: reason={last.get('reason')} exitCode={code}"],
                **base,
            )
        ]

    if "running" in state and not cs.get("ready", True):
        probe = _match_event(events, r"readiness probe failed")
        if probe:
            return [
                Finding(
                    WARNING,
                    reason="NotReady",
                    summary="Running but failing readiness: getting no traffic.",
                    next_step="Check the readiness endpoint and what it depends on (DB, downstream).",
                    evidence=[probe],
                    **base,
                )
            ]

    if restarts >= FLAPPING_RESTARTS and "running" in state:
        return [
            Finding(
                WARNING,
                reason="Flapping",
                summary=f"Running now, but restarted {restarts} times.",
                next_step="Look at the previous container's logs and exit reason before it hides again.",
                evidence=[f"lastState.terminated: reason={last.get('reason')} exitCode={last.get('exitCode')}"],
                **base,
            )
        ]
    return []


def _pending_finding(pod: dict[str, Any], events: list[dict[str, Any]]) -> Finding | None:
    meta = pod.get("metadata", {})
    status = pod.get("status", {})
    if status.get("phase") != "Pending":
        return None
    for cond in status.get("conditions") or []:
        if cond.get("type") == "PodScheduled" and cond.get("status") == "False":
            msg = cond.get("message", "") or (_match_event(events, r"FailedScheduling") or "")
            if re.search(r"insufficient (cpu|memory)", msg, re.I):
                step = "Requests are bigger than any node has free. Lower requests or add capacity."
            elif re.search(r"unbound.*persistentvolumeclaim|persistentvolumeclaim.*not found", msg, re.I):
                step = "The PVC isn't bound. Check the StorageClass and the PVC's events."
            elif re.search(r"taint", msg, re.I):
                step = "Every node has a taint this pod doesn't tolerate. Add a toleration or fix node pools."
            elif re.search(r"affinity|selector", msg, re.I):
                step = "No node matches the nodeSelector/affinity. Check node labels."
            else:
                step = "Read the FailedScheduling event for the scheduler's reasoning."
            return Finding(
                CRITICAL,
                meta.get("namespace", ""),
                meta.get("name", ""),
                "Unschedulable",
                "Stuck in Pending: the scheduler can't place it.",
                step,
                evidence=[msg] if msg else [],
            )
    return None


def diagnose_pod(pod: dict[str, Any], events: list[dict[str, Any]] | None = None) -> list[Finding]:
    """All findings for one pod. Empty list means healthy."""
    events = events or []
    status = pod.get("status", {})
    meta = pod.get("metadata", {})

    if status.get("phase") == "Succeeded":
        return []
    if status.get("reason") == "Evicted":
        return [
            Finding(
                WARNING,
                meta.get("namespace", ""),
                meta.get("name", ""),
                "Evicted",
                f"Evicted: {status.get('message', 'node pressure')}",
                "Node was under pressure. Check node conditions and this pod's requests vs usage.",
            )
        ]

    pending = _pending_finding(pod, events)
    if pending:
        return [pending]

    findings: list[Finding] = []
    for cs in (status.get("initContainerStatuses") or []) + (status.get("containerStatuses") or []):
        findings.extend(_container_findings(pod, cs, events))
    return findings


def diagnose_node(node: dict[str, Any]) -> Finding | None:
    name = node.get("metadata", {}).get("name", "")
    for cond in node.get("status", {}).get("conditions") or []:
        t, s = cond.get("type"), cond.get("status")
        if t == "Ready" and s != "True":
            return Finding(
                CRITICAL,
                "",
                name,
                "NodeNotReady",
                f"Node {name} is NotReady.",
                "Check kubelet and the node's cloud instance; pods on it will be evicted.",
                evidence=[cond.get("message", "")],
            )
        if t in ("MemoryPressure", "DiskPressure", "PIDPressure") and s == "True":
            return Finding(
                WARNING,
                "",
                name,
                t,
                f"Node {name} has {t}.",
                "Pods may get evicted. Find the heavy pods on this node.",
                evidence=[cond.get("message", "")],
            )
    return None


def rank(findings: list[Finding]) -> list[Finding]:
    order = {CRITICAL: 0, WARNING: 1}
    return sorted(findings, key=lambda f: (order.get(f.severity, 2), f.namespace, f.pod))
