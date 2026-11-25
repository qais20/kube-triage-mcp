"""Drive the real server over stdio against a real cluster, the way an agent would.

Usage: python scripts/e2e.py   (expects examples/broken-shop.yaml applied, KUBECONFIG set)
Exits non-zero if any expected failure isn't diagnosed.
"""

import asyncio
import json
import os
import sys
import tempfile

from mcp import Client, StdioServerParameters

EXPECTED = {
    "api": "CrashLoop",
    "worker": "OOMKilled",
    "web": "ImagePull",
    "batch": "Unschedulable",
    "checkout": "NotReady",
    "payments": "ConfigError",
}


def show(title, data):
    print(f"\n── {title} " + "─" * max(0, 60 - len(title)))
    print(json.dumps(data, indent=2)[:2500])


async def main() -> int:
    tmp = tempfile.mkdtemp()
    params = StdioServerParameters(
        command=sys.executable,
        args=[
            "-m",
            "kube_triage_mcp",
            "--namespaces",
            "demo-shop",
            "--allow-writes",
            "--audit-log",
            f"{tmp}/audit.jsonl",
            "--stop-file",
            f"{tmp}/STOP",
        ],
        env={**os.environ},
    )
    async with Client(params) as c:
        tools = [t.name for t in (await c.list_tools()).tools]
        print("tools:", ", ".join(tools))

        # Crash loops and OOM kills take a few restarts to show up; poll for up to 3 minutes.
        for _ in range(36):
            triage = (await c.call_tool("triage", {})).structured_content
            seen = {f["pod"].split("-")[0]: f["reason"] for f in triage["findings"]}
            if all(seen.get(k) == v for k, v in EXPECTED.items()):
                break
            await asyncio.sleep(5)
        print(f"\ntriage: {len(triage['findings'])} findings, pods {triage['pods']}")
        for f in triage["findings"]:
            print(f"  [{f['severity']:8}] {f['pod'][:30]:30} {f['reason']:14} {f['summary']}")
        got = {f["pod"].split("-")[0]: f["reason"] for f in triage["findings"]}
        missing = {k: v for k, v in EXPECTED.items() if got.get(k) != v}

        api_pod = next(f["pod"] for f in triage["findings"] if f["pod"].startswith("api-"))
        explain = (await c.call_tool("explain_pod", {"namespace": "demo-shop", "pod": api_pod})).structured_content
        show("explain_pod api: crash_logs", explain.get("crash_logs"))
        leaked = "hunter2" in json.dumps(explain)
        logs_ok = "FATAL" in json.dumps(explain.get("crash_logs"))

        scope = await c.call_tool("triage", {"namespace": "kube-system"})
        print("\nout-of-scope namespace refused:", scope.is_error)

        plan = (
            await c.call_tool("propose_restart", {"namespace": "demo-shop", "deployment": "catalog", "reason": "e2e"})
        ).structured_content
        show("propose_restart", plan)
        done = await c.call_tool("execute", {"token": plan["token"]})
        show("execute", done.structured_content)
        replay = await c.call_tool("execute", {"token": plan["token"]})
        print("\ntoken replay refused:", replay.is_error)

    print("\naudit log:", sum(1 for _ in open(f"{tmp}/audit.jsonl")), "entries")
    ok = logs_ok and not missing and not leaked and scope.is_error and not done.is_error and replay.is_error
    if missing:
        print("MISSED:", missing)
    if not logs_ok:
        print("NO CRASH LOGS in explain_pod")
    if leaked:
        print("LEAK: secret reached the model")
    print("\nE2E", "PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
