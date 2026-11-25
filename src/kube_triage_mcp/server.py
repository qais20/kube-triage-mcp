"""The MCP server: tools a model uses to triage a Kubernetes incident."""

from __future__ import annotations

import functools
from collections import defaultdict
from collections.abc import Callable
from typing import Any

from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.types import ToolAnnotations

from .diagnose import diagnose_node, diagnose_pod, rank
from .guard import Guard, GuardError
from .kube import KubeAPI, restart_patch
from .redact import redact

INSTRUCTIONS = """\
You are helping an on-call engineer triage a Kubernetes incident.
Start with `triage` for the whole picture, then `explain_pod` on the worst finding.
Read logs with `get_logs` (previous=true for a crashed container).
Before suggesting a rollback, check `rollout_status`: a new revision right before
the failures started is the usual suspect.
Changes are two-step: `propose_restart` / `propose_scale` return a plan and a token.
Show the plan to the human and only call `execute` after they say yes.
Never claim a fix worked until `triage` comes back clean.
"""

READ = ToolAnnotations(read_only_hint=True, open_world_hint=False)
LOG_LIMIT = 500


def _event_row(e: dict[str, Any]) -> dict[str, Any]:
    obj = e.get("involvedObject") or {}
    return {
        "type": e.get("type"),
        "reason": e.get("reason"),
        "object": f"{obj.get('kind', '')}/{obj.get('name', '')}",
        "namespace": obj.get("namespace"),
        "message": (e.get("message") or "").strip()[:300],
        "count": e.get("count") or 1,
        "last_seen": e.get("lastTimestamp") or e.get("eventTime"),
    }


def build_server(kube: KubeAPI, guard: Guard, cluster_name: str = "cluster") -> MCPServer:
    mcp = MCPServer(
        name="kube-triage",
        title="Kubernetes incident triage",
        instructions=INSTRUCTIONS,
        version="0.1.0",
    )

    def audited(fn: Callable[..., Any]) -> Callable[..., Any]:
        @functools.wraps(fn)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            guard.audit("call", tool=fn.__name__, args=kwargs)
            try:
                return fn(*args, **kwargs)
            except ToolError:
                raise
            except Exception as exc:  # kubernetes ApiException and friends
                status = getattr(exc, "status", None)
                if status == 404:
                    raise ToolError("Not found. Check the namespace and name (use triage to list pods).") from exc
                if status == 403:
                    raise ToolError("Forbidden by RBAC. This server's service account can't do that.") from exc
                raise

        return wrapper

    def _events_by_object(namespace: str | None) -> dict[tuple[str, str], list[dict[str, Any]]]:
        grouped: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
        for e in kube.list_events(namespace):
            obj = e.get("involvedObject") or {}
            grouped[(obj.get("namespace", ""), obj.get("name", ""))].append(e)
        return grouped

    # ---------------------------------------------------------------- reads --
    @mcp.tool(annotations=READ)
    @audited
    def triage(namespace: str | None = None) -> dict[str, Any]:
        """Scan the cluster (or one namespace) and return ranked findings: what's broken, why, and what to check next.

        Covers CrashLoopBackOff, OOMKilled, image pull failures, missing config, unschedulable
        pods, failing probes, flapping containers, evictions and unhealthy nodes. Start here.
        """
        guard.check_namespace(namespace)
        namespaces = [namespace] if namespace else (sorted(guard.namespaces) or [None])
        pods: list[dict[str, Any]] = []
        events: dict[tuple[str, str], list[dict[str, Any]]] = {}
        for ns in namespaces:
            pods += [p for p in kube.list_pods(ns) if guard.visible(p["metadata"]["namespace"])]
            events |= _events_by_object(ns)

        findings = []
        for p in pods:
            m = p["metadata"]
            findings += diagnose_pod(p, events.get((m["namespace"], m["name"]), []))
        if not namespace:
            findings += [f for f in (diagnose_node(n) for n in kube.list_nodes()) if f]
        findings = rank(findings)

        phases: dict[str, int] = defaultdict(int)
        for p in pods:
            phases[p.get("status", {}).get("phase", "Unknown")] += 1
        return {
            "cluster": cluster_name,
            "scope": namespace or (sorted(guard.namespaces) if guard.namespaces else "all namespaces"),
            "pods": dict(phases),
            "healthy": not findings,
            "findings": [f.to_dict() for f in findings],
        }

    @mcp.tool(annotations=READ)
    @audited
    def explain_pod(namespace: str, pod: str) -> dict[str, Any]:
        """Deep dive on one pod: diagnosis, container states, recent events, last log lines of a crash."""
        guard.check_namespace(namespace)
        p = kube.get_pod(namespace, pod)
        evs = kube.list_events(namespace, involved=pod)
        findings = diagnose_pod(p, evs)
        status = p.get("status", {})

        containers = []
        for cs in status.get("containerStatuses") or []:
            state = next(iter((cs.get("state") or {}).keys()), "unknown")
            containers.append(
                {
                    "name": cs.get("name"),
                    "image": cs.get("image"),
                    "state": state,
                    "ready": cs.get("ready"),
                    "restarts": cs.get("restartCount", 0),
                    "last_termination": ((cs.get("lastState") or {}).get("terminated") or {}).get("reason"),
                }
            )

        out: dict[str, Any] = {
            "pod": f"{namespace}/{pod}",
            "phase": status.get("phase"),
            "node": p.get("spec", {}).get("nodeName"),
            "owner": next((f"{o['kind']}/{o['name']}" for o in p["metadata"].get("ownerReferences") or []), None),
            "findings": [f.to_dict() for f in rank(findings)],
            "containers": containers,
            # Warnings first; the Normal "Pulled/Created/Started" noise last.
            "events": [_event_row(e) for e in sorted(evs, key=lambda e: e.get("type") != "Warning")[:10]],
        }

        crashed = next((f.container for f in findings if f.reason in ("CrashLoop", "OOMKilled", "LivenessProbe")), None)
        if crashed:
            # If the container is sitting in `terminated`, its own logs are the crash.
            # If it's back-off waiting, the crash lives in the previous instance.
            st = next((c for c in containers if c["name"] == crashed), {}).get("state")
            for previous in (st != "terminated", st == "terminated"):
                try:
                    raw = kube.pod_logs(namespace, pod, crashed, previous=previous, tail=30)
                except Exception:
                    continue
                if raw.strip() and not raw.startswith("unable to retrieve container logs"):
                    text, n = redact(raw)
                    out["crash_logs"] = {
                        "container": crashed,
                        "previous": previous,
                        "tail": text.splitlines()[-30:],
                        "redactions": n,
                    }
                    break
        return out

    @mcp.tool(annotations=READ)
    @audited
    def get_logs(
        namespace: str, pod: str, container: str | None = None, previous: bool = False, tail_lines: int = 100
    ) -> dict[str, Any]:
        """Tail a container's logs, secrets redacted. previous=true reads the last crashed instance."""
        guard.check_namespace(namespace)
        tail = max(1, min(tail_lines, LOG_LIMIT))
        text, n = redact(kube.pod_logs(namespace, pod, container, previous, tail))
        lines = text.splitlines()
        return {
            "pod": f"{namespace}/{pod}",
            "container": container,
            "previous": previous,
            "lines": lines,
            "line_count": len(lines),
            "redactions": n,
        }

    @mcp.tool(annotations=READ)
    @audited
    def list_events(namespace: str | None = None, warnings_only: bool = True, limit: int = 30) -> dict[str, Any]:
        """Recent cluster events, newest first. Warnings only by default."""
        guard.check_namespace(namespace)
        namespaces = [namespace] if namespace else (sorted(guard.namespaces) or [None])
        evs = [
            e
            for ns in namespaces
            for e in kube.list_events(ns)
            if guard.visible((e.get("involvedObject") or {}).get("namespace", ""))
        ]
        if warnings_only:
            evs = [e for e in evs if e.get("type") == "Warning"]
        evs.sort(key=lambda e: e.get("lastTimestamp") or e.get("eventTime") or "", reverse=True)
        return {"events": [_event_row(e) for e in evs[: max(1, min(limit, 200))]]}

    @mcp.tool(annotations=READ)
    @audited
    def rollout_status(namespace: str, deployment: str) -> dict[str, Any]:
        """A deployment's health and revision history (image per revision). Use it to spot a bad release."""
        guard.check_namespace(namespace)
        d = kube.get_deployment(namespace, deployment)
        spec, st = d.get("spec", {}), d.get("status", {})
        sel = ",".join(f"{k}={v}" for k, v in (spec.get("selector", {}).get("matchLabels") or {}).items())
        revisions = []
        for rs in kube.list_replicasets(namespace, sel):
            if not any(o.get("name") == deployment for o in rs["metadata"].get("ownerReferences") or []):
                continue
            ann = rs["metadata"].get("annotations") or {}
            revisions.append(
                {
                    "revision": int(ann.get("deployment.kubernetes.io/revision", 0)),
                    "images": [c.get("image") for c in rs["spec"]["template"]["spec"].get("containers", [])],
                    "replicas": rs.get("status", {}).get("replicas", 0),
                    "ready": rs.get("status", {}).get("readyReplicas", 0),
                    "created": rs["metadata"].get("creationTimestamp"),
                }
            )
        revisions.sort(key=lambda r: r["revision"], reverse=True)
        return {
            "deployment": f"{namespace}/{deployment}",
            "desired": spec.get("replicas"),
            "ready": st.get("readyReplicas", 0),
            "updated": st.get("updatedReplicas", 0),
            "available": st.get("availableReplicas", 0),
            "conditions": [
                {
                    "type": c.get("type"),
                    "status": c.get("status"),
                    "reason": c.get("reason"),
                    "message": c.get("message"),
                }
                for c in st.get("conditions") or []
            ],
            "revisions": revisions[:5],
        }

    # --------------------------------------------------------------- writes --
    def _plan_out(plan) -> dict[str, Any]:
        return {
            "token": plan.token,
            "plan": plan.summary,
            "expires_in_seconds": guard.ttl_seconds,
            "next": "Show this plan to the human. Call execute(token) only after they approve.",
        }

    @mcp.tool(annotations=ToolAnnotations(read_only_hint=False, destructive_hint=False, idempotent_hint=True))
    @audited
    def propose_restart(namespace: str, deployment: str, reason: str) -> dict[str, Any]:
        """Plan a rolling restart of a deployment. Changes nothing; returns a plan and a single-use token."""
        guard.check_namespace(namespace)
        d = kube.get_deployment(namespace, deployment)
        n = d.get("spec", {}).get("replicas", 0)
        summary = (
            f"Rolling restart of {namespace}/{deployment} ({n} replicas, one at a time per its strategy). "
            f"Reason: {reason}"
        )
        return _plan_out(guard.propose("restart", namespace, deployment, {"reason": reason}, summary))

    @mcp.tool(annotations=ToolAnnotations(read_only_hint=False, destructive_hint=False, idempotent_hint=True))
    @audited
    def propose_scale(namespace: str, deployment: str, replicas: int, reason: str) -> dict[str, Any]:
        """Plan scaling a deployment. Changes nothing; returns a plan and a single-use token."""
        guard.check_namespace(namespace)
        if not 0 <= replicas <= 50:
            raise GuardError("Replicas must be between 0 and 50.")
        current = kube.get_deployment(namespace, deployment).get("spec", {}).get("replicas", 0)
        warn = " WARNING: 0 replicas takes the service offline." if replicas == 0 else ""
        summary = f"Scale {namespace}/{deployment} from {current} to {replicas} replicas. Reason: {reason}.{warn}"
        return _plan_out(
            guard.propose(
                "scale", namespace, deployment, {"replicas": replicas, "from": current, "reason": reason}, summary
            )
        )

    @mcp.tool(annotations=ToolAnnotations(read_only_hint=False, destructive_hint=True, idempotent_hint=False))
    @audited
    def execute(token: str) -> dict[str, Any]:
        """Carry out a plan a human approved. Needs the token from propose_*. Single use, expires in 5 minutes."""
        plan = guard.take(token)
        if plan.action == "restart":
            kube.patch_deployment(plan.namespace, plan.target, restart_patch())
        elif plan.action == "scale":
            kube.scale_deployment(plan.namespace, plan.target, plan.params["replicas"])
        else:  # pragma: no cover
            raise GuardError(f"Unknown action {plan.action}")
        guard.audit(
            "execute", action=plan.action, namespace=plan.namespace, target=plan.target, params=plan.params, token=token
        )
        return {
            "done": plan.summary,
            "verify": f"Run rollout_status('{plan.namespace}', '{plan.target}') then triage to confirm.",
        }

    @mcp.prompt()
    def incident(symptom: str) -> str:
        """Kick off a triage session from a symptom ("checkout is 500ing")."""
        return (
            f"Users report: {symptom}\n\n"
            "Triage the cluster. Find the most likely cause, show evidence (events, logs, revisions), "
            "and propose the smallest safe fix. Don't execute anything without my approval."
        )

    return mcp
