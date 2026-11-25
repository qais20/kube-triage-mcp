"""CLI entry point: `kube-triage-mcp [--http] [--allow-writes] [--namespaces a,b]`."""

from __future__ import annotations

import argparse
import hmac
import os
import sys
from pathlib import Path

from .guard import Guard
from .kube import LiveKube
from .server import build_server


def _parse(argv: list[str] | None) -> argparse.Namespace:
    p = argparse.ArgumentParser(prog="kube-triage-mcp", description="Kubernetes incident triage over MCP.")
    p.add_argument("--context", help="kubeconfig context (default: current, or in-cluster)")
    p.add_argument(
        "--namespaces", default=os.getenv("KUBE_TRIAGE_NAMESPACES", ""), help="comma-separated allow-list; default all"
    )
    p.add_argument(
        "--allow-writes",
        action="store_true",
        default=os.getenv("KUBE_TRIAGE_ALLOW_WRITES") == "true",
        help="enable propose/execute (restart, scale)",
    )
    p.add_argument(
        "--stop-file",
        type=Path,
        default=Path(os.getenv("KUBE_TRIAGE_STOP_FILE", Path.home() / ".kube-triage" / "STOP")),
        help="kill switch: if this file exists, every write is refused",
    )
    p.add_argument(
        "--audit-log",
        type=Path,
        default=Path(os.getenv("KUBE_TRIAGE_AUDIT_LOG", Path.home() / ".kube-triage" / "audit.jsonl")),
    )
    p.add_argument("--http", action="store_true", help="serve streamable HTTP instead of stdio")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8080)
    return p.parse_args(argv)


def _bearer(app, token: str):
    """Refuse any HTTP request without the shared bearer token (constant-time compare)."""
    expected = f"Bearer {token}".encode()

    async def guarded(scope, receive, send):
        if scope["type"] == "http" and scope["path"] != "/healthz":
            got = dict(scope.get("headers") or []).get(b"authorization", b"")
            if not hmac.compare_digest(got, expected):
                await send(
                    {"type": "http.response.start", "status": 401, "headers": [(b"content-type", b"text/plain")]}
                )
                await send({"type": "http.response.body", "body": b"unauthorized\n"})
                return
        if scope["type"] == "http" and scope["path"] == "/healthz":
            await send({"type": "http.response.start", "status": 200, "headers": [(b"content-type", b"text/plain")]})
            await send({"type": "http.response.body", "body": b"ok\n"})
            return
        await app(scope, receive, send)

    return guarded


def main(argv: list[str] | None = None) -> None:
    args = _parse(argv)
    guard = Guard(
        allow_writes=args.allow_writes,
        namespaces=frozenset(n.strip() for n in args.namespaces.split(",") if n.strip()),
        stop_file=args.stop_file,
        audit_log=args.audit_log,
    )
    server = build_server(LiveKube(args.context), guard, cluster_name=args.context or "current-context")

    if not args.http:
        server.run("stdio")
        return

    token = os.getenv("KUBE_TRIAGE_TOKEN")
    if not token:
        sys.exit("KUBE_TRIAGE_TOKEN must be set for --http. Refusing to serve a cluster without auth.")
    import uvicorn
    from mcp.server.transport_security import TransportSecuritySettings

    sec = None
    if args.host not in ("127.0.0.1", "localhost"):
        # Behind a load balancer the Host header is the public name; auth is the bearer token.
        sec = TransportSecuritySettings(enable_dns_rebinding_protection=False)
    app = server.streamable_http_app(host=args.host, transport_security=sec)
    uvicorn.run(_bearer(app, token), host=args.host, port=args.port, log_level="info")


if __name__ == "__main__":
    main()
