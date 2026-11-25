"""End-to-end through the MCP protocol, in-process, against a fake cluster."""

import json

import pytest
from mcp import Client

from kube_triage_mcp.guard import Guard
from kube_triage_mcp.server import build_server

from .fakes import FakeKube

pytestmark = pytest.mark.anyio


@pytest.fixture
def anyio_backend():
    return "asyncio"


def make(tmp_path, kube=None, **guard_kw):
    kube = kube or FakeKube()
    guard = Guard(stop_file=tmp_path / "STOP", audit_log=tmp_path / "audit.jsonl", **guard_kw)
    return build_server(kube, guard), kube, guard


async def call(server, tool, **args):
    async with Client(server) as c:
        r = await c.call_tool(tool, args)
    text = r.content[0].text if r.content else ""
    return r, (r.structured_content if r.structured_content is not None else text)


async def test_tools_are_annotated(tmp_path):
    server, *_ = make(tmp_path)
    async with Client(server) as c:
        tools = {t.name: t for t in (await c.list_tools()).tools}
    assert tools["triage"].annotations.read_only_hint is True
    assert tools["execute"].annotations.destructive_hint is True


async def test_triage_ranks_findings(tmp_path):
    server, *_ = make(tmp_path)
    _, out = await call(server, "triage")
    reasons = {f["reason"] for f in out["findings"]}
    assert {"CrashLoop", "OOMKilled", "ImagePull", "Unschedulable"} <= reasons
    assert out["healthy"] is False


async def test_namespace_allow_list_hides_other_namespaces(tmp_path):
    server, *_ = make(tmp_path, namespaces=frozenset({"shop"}))
    _, out = await call(server, "triage")
    assert all(f["namespace"] == "shop" for f in out["findings"])
    r, text = await call(server, "explain_pod", namespace="payments", pod="secret-thing")
    assert r.is_error and "outside this server's scope" in text


async def test_explain_pod_includes_redacted_previous_logs(tmp_path):
    kube = FakeKube(logs="boot\nDB_PASSWORD=hunter2\npanic: cannot connect")
    server, *_ = make(tmp_path, kube)
    _, out = await call(server, "explain_pod", namespace="shop", pod="api-7c9-crash")
    logs = out["crash_logs"]
    assert "hunter2" not in json.dumps(logs) and logs["redactions"] == 1


async def test_not_found_is_a_clean_error(tmp_path):
    server, *_ = make(tmp_path)
    r, text = await call(server, "explain_pod", namespace="shop", pod="nope")
    assert r.is_error and "Not found" in text


async def test_writes_disabled_by_default(tmp_path):
    server, kube, _ = make(tmp_path)
    r, text = await call(server, "propose_restart", namespace="shop", deployment="api", reason="test")
    assert r.is_error and "Writes are disabled" in text and kube.writes == []


async def test_propose_then_execute(tmp_path):
    server, kube, guard = make(tmp_path, allow_writes=True)
    async with Client(server) as c:
        plan = (
            await c.call_tool(
                "propose_scale", {"namespace": "shop", "deployment": "api", "replicas": 5, "reason": "load"}
            )
        ).structured_content
        assert "from 3 to 5" in plan["plan"] and kube.writes == []
        done = await c.call_tool("execute", {"token": plan["token"]})
        assert not done.is_error
        again = await c.call_tool("execute", {"token": plan["token"]})
    assert kube.writes == [("scale", "shop", "api", 5)]
    assert again.is_error  # single use
    events = [json.loads(line)["event"] for line in guard.audit_log.read_text().splitlines()]
    assert "propose" in events and "execute" in events


async def test_kill_switch_blocks_execute_after_propose(tmp_path):
    server, kube, guard = make(tmp_path, allow_writes=True)
    async with Client(server) as c:
        plan = (
            await c.call_tool("propose_restart", {"namespace": "shop", "deployment": "api", "reason": "stuck"})
        ).structured_content
        guard.stop_file.touch()
        r = await c.call_tool("execute", {"token": plan["token"]})
    assert r.is_error and "Kill switch" in r.content[0].text and kube.writes == []


async def test_bogus_token_refused(tmp_path):
    server, kube, _ = make(tmp_path, allow_writes=True)
    r, text = await call(server, "execute", token="made-up")
    assert r.is_error and kube.writes == []
