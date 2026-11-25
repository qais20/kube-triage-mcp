"""Guardrails between a model and a production cluster.

- Reads are scoped to an allow-list of namespaces (or everything).
- Writes are off unless the operator turns them on.
- Every write is two steps: propose -> human reads the plan -> execute with a
  single-use token that expires. The model can't skip the plan.
- A kill switch file stops every write instantly, no restart needed.
- Every call lands in an append-only JSONL audit log.
"""

from __future__ import annotations

import json
import secrets
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from mcp.server.mcpserver.exceptions import ToolError


class GuardError(ToolError):
    """Refused by policy. The message is safe to show to the model."""


@dataclass
class Plan:
    token: str
    action: str
    namespace: str
    target: str
    params: dict[str, Any]
    summary: str
    expires_at: float


@dataclass
class Guard:
    allow_writes: bool = False
    namespaces: frozenset[str] = frozenset()  # empty = all namespaces
    stop_file: Path = Path.home() / ".kube-triage" / "STOP"
    audit_log: Path | None = Path.home() / ".kube-triage" / "audit.jsonl"
    ttl_seconds: int = 300
    _plans: dict[str, Plan] = field(default_factory=dict)

    # -- scope ---------------------------------------------------------------
    def check_namespace(self, namespace: str | None) -> None:
        if namespace and self.namespaces and namespace not in self.namespaces:
            raise GuardError(f"Namespace '{namespace}' is outside this server's scope: {sorted(self.namespaces)}.")

    def visible(self, namespace: str) -> bool:
        return not self.namespaces or namespace in self.namespaces

    # -- writes --------------------------------------------------------------
    def _check_writes(self) -> None:
        if not self.allow_writes:
            raise GuardError("Writes are disabled. Start the server with --allow-writes to enable proposals.")
        if self.stop_file.exists():
            raise GuardError(f"Kill switch is on ({self.stop_file}). All writes are refused.")

    def propose(self, action: str, namespace: str, target: str, params: dict[str, Any], summary: str) -> Plan:
        self._check_writes()
        self.check_namespace(namespace)
        self._expire()
        plan = Plan(
            secrets.token_urlsafe(9), action, namespace, target, params, summary, time.time() + self.ttl_seconds
        )
        self._plans[plan.token] = plan
        self.audit("propose", action=action, namespace=namespace, target=target, params=params, token=plan.token)
        return plan

    def take(self, token: str) -> Plan:
        """Consume a plan. Single use; re-checks policy at execution time."""
        self._check_writes()
        self._expire()
        plan = self._plans.pop(token, None)
        if plan is None:
            self.audit("refused", reason="unknown or expired token")
            raise GuardError("Unknown or expired token. Propose the action again and show the plan to a human.")
        self.check_namespace(plan.namespace)
        return plan

    def _expire(self) -> None:
        now = time.time()
        for t in [t for t, p in self._plans.items() if p.expires_at < now]:
            del self._plans[t]

    # -- audit ---------------------------------------------------------------
    def audit(self, event: str, **fields: Any) -> None:
        if self.audit_log is None:
            return
        self.audit_log.parent.mkdir(parents=True, exist_ok=True)
        rec = {"ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "event": event, **fields}
        with self.audit_log.open("a") as f:
            f.write(json.dumps(rec, default=str) + "\n")
