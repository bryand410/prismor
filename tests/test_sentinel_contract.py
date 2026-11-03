"""S-CON and S-CLI: dispatch, system sync, background flush, and the CLI."""
from __future__ import annotations

import json
import sys
import time
from pathlib import Path

import pytest

from prismor.runtime.sentinel.auth import clear_cache
from prismor.runtime.sentinel.mapping import dumps_row
from tests.sentinel_fake import FakeAzure
from tests.sentinel_support import ingest_requests, sink_dict, token_requests

ROOT = Path(__file__).resolve().parents[1]
GOLDEN = ROOT / "tests" / "golden" / "sentinel"
FIXTURES = ROOT / "tests" / "sentinel_fixtures"


def setup_function():
    clear_cache()


def _freeze(monkeypatch):
    from datetime import datetime, timezone
    import prismor.runtime.sinks as sinks

    class Frozen(datetime):
        @classmethod
        def now(cls, tz=None):
            return datetime(2026, 8, 30, 18, 4, 11, tzinfo=timezone.utc)

    monkeypatch.setattr(sinks, "datetime", Frozen)
    monkeypatch.setattr(sinks, "_hostname", lambda: "laptop.local")
    monkeypatch.setattr(
        "prismor.runtime.enterprise.identity.load_identity",
        lambda: {"device_id": "device-fixture", "device_key": "k"},
    )


def _allow(monkeypatch, tmp_path):
    monkeypatch.setenv("PRISMOR_SENTINEL_ALLOW_INSECURE_LOCALHOST", "1")
    monkeypatch.setenv("PRISMOR_HOME", str(tmp_path))


def test_sinks_import_does_not_load_sentinel():
    script = (
        "import sys\n"
        "from prismor.runtime.sinks import dispatch\n"
        "dispatch([{'severity':'LOW','ruleId':'r','title':'t','evidence':'e','id':'s:1'}],"
        "[{'type':'file','path':'/tmp/prismor-sentinel-import-check.log'}])\n"
        "loaded = [n for n in sys.modules if n.startswith('prismor.runtime.sentinel')]\n"
        "print('loaded' if loaded else 'clean')\n"
    )
    import subprocess
    out = subprocess.check_output([sys.executable, "-c", script], text=True).strip()
    assert out == "clean"


def test_s_con_01_dispatch_matches_golden(tmp_path, monkeypatch):
    _allow(monkeypatch, tmp_path)
    _freeze(monkeypatch)
    fake = FakeAzure()
    finding = json.loads((FIXTURES / "finding_block.json").read_text(encoding="utf-8"))
    try:
        from prismor.runtime.sinks import dispatch
        dispatch([finding], [sink_dict(fake, gzip=False, delivery="inline", flush_on_block=True)])
    finally:
        fake.close()
    posted = ingest_requests(fake)
    assert len(token_requests(fake)) == 1
    assert len(posted) == 1
    assert posted[0]["path"].endswith("/streams/Custom-PrismorAgentEvents")
    body = json.loads(posted[0]["body"].decode("utf-8"))
    assert dumps_row(body[0]) + "\n" == (GOLDEN / "agent_event_block.json").read_text(encoding="utf-8")


def test_s_con_02_strict_schema_accepts_goldens(tmp_path, monkeypatch):
    _allow(monkeypatch, tmp_path)
    _freeze(monkeypatch)
    columns = json.loads((ROOT / "packaging/sentinel/bicep/schema/agent_events.stream.json").read_text(encoding="utf-8"))
    fake = FakeAzure()
    fake.strict_columns = {item["name"] for item in columns}
    finding = json.loads((FIXTURES / "finding_block.json").read_text(encoding="utf-8"))
    try:
        from prismor.runtime.sinks import dispatch
        dispatch([finding], [sink_dict(fake, gzip=False)])
    finally:
        fake.close()
    posted = ingest_requests(fake)
    assert posted and posted[-1].get("status") == 204


def test_s_con_03_inventory_dispatch(tmp_path, monkeypatch):
    _allow(monkeypatch, tmp_path)
    fake = FakeAzure()
    records = [
        json.loads((FIXTURES / "inventory_cps_agent.json").read_text(encoding="utf-8")),
        json.loads((FIXTURES / "inventory_mcp_endpoint.json").read_text(encoding="utf-8")),
    ]
    try:
        from prismor.runtime.sinks import dispatch_inventory
        dispatch_inventory(records, [sink_dict(fake, gzip=False, streams={"events": "", "inventory": "Custom-PrismorAIInventory"})])
    finally:
        fake.close()
    posted = [item for item in ingest_requests(fake) if item.get("status") == 204]
    assert posted
    assert posted[0]["path"].endswith("/streams/Custom-PrismorAIInventory")
    rows = json.loads(posted[0]["body"].decode("utf-8"))
    assert len(rows) == 2
    assert dumps_row(rows[0]) + "\n" == (GOLDEN / "inventory_cps_agent.json").read_text(encoding="utf-8")
    assert dumps_row(rows[1]) + "\n" == (GOLDEN / "inventory_mcp_endpoint.json").read_text(encoding="utf-8")


def test_s_con_04_system_sync_drains_homes(tmp_path, monkeypatch):
    _allow(monkeypatch, tmp_path)
    _freeze(monkeypatch)
    homes = [tmp_path / "alice" / ".prismor", tmp_path / "bob" / ".prismor"]
    for home in homes:
        home.mkdir(parents=True)
    fake = FakeAzure()
    sink = sink_dict(fake, delivery="system", gzip=False)
    finding = json.loads((FIXTURES / "finding_block.json").read_text(encoding="utf-8"))
    chowned = []
    try:
        from prismor.runtime.sinks import dispatch
        for home in homes:
            monkeypatch.setenv("PRISMOR_HOME", str(home))
            before = len(fake.requests)
            dispatch([finding], [sink])
            assert len(fake.requests) == before
        monkeypatch.setattr("prismor.runtime.system_install.os.chown", lambda path, uid, gid: chowned.append(str(path)))
        monkeypatch.setattr("prismor.runtime.enterprise.remote_policy.fetch", lambda force=False: True)
        monkeypatch.setattr("prismor.runtime.sinks.upload_telemetry", lambda *args, **kwargs: None)
        monkeypatch.setattr("prismor.runtime.system_install.user_prismor_homes", lambda: homes)
        monkeypatch.setattr("prismor.runtime.sentinel.configured_sinks", lambda outputs=None: [sink])
        from prismor.runtime.system_install import sync
        sync()
    finally:
        fake.close()
    assert len(token_requests(fake)) == 1
    assert len([item for item in ingest_requests(fake) if item.get("status") == 204]) == 2
    for home in homes:
        spool = home / "sentinel-hmlr-sentinel-events.jsonl"
        assert spool.read_text(encoding="utf-8").strip() == ""
    assert any("sentinel-" in path for path in chowned)


def test_s_con_05_background_kick(tmp_path, monkeypatch):
    _allow(monkeypatch, tmp_path)
    fake = FakeAzure()
    import prismor.runtime.sentinel as sentinel
    from prismor.runtime.enterprise import heartbeat
    from prismor.runtime.sentinel.delivery import set_background
    monkeypatch.setattr(heartbeat, "maybe_flush", heartbeat.maybe_flush)
    sink = sink_dict(fake, delivery="auto", gzip=False, flush_interval_seconds=30)
    try:
        sentinel.start_background([sink])
        from prismor.runtime.sinks import dispatch
        dispatch([{"severity": "LOW", "ruleId": "r", "title": "t", "evidence": "e",
                   "id": "s:1", "action": "allow"}], [sink])
        time.sleep(0.35)
        assert ingest_requests(fake) == []
        dispatch([{"severity": "HIGH", "ruleId": "r", "title": "t", "evidence": "e",
                   "id": "s:2", "action": "block"}], [sink])
        deadline = time.monotonic() + 1.0
        while time.monotonic() < deadline and not ingest_requests(fake):
            time.sleep(0.05)
        assert ingest_requests(fake)
    finally:
        sentinel._BG_SINKS.clear()
        set_background(False)
        fake.close()


def test_s_con_06_min_severity_filters(tmp_path, monkeypatch):
    _allow(monkeypatch, tmp_path)
    fake = FakeAzure()
    try:
        from prismor.runtime.sentinel import enqueue_events
        enqueue_events(sink_dict(fake, min_severity="HIGH", delivery="system"), [{
            "rule_id": "r", "severity": "LOW", "@timestamp": "2026-11-02T00:00:00Z",
        }])
    finally:
        fake.close()
    assert not (tmp_path / "sentinel-hmlr-sentinel-events.jsonl").exists()
    health = json.loads((tmp_path / "sentinel-hmlr-sentinel-health.json").read_text(encoding="utf-8"))
    assert health["streams"]["events"]["dropped"]["filtered"] == 1


def test_s_con_07_file_sink_still_writes(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("PRISMOR_HOME", str(tmp_path))
    from prismor.runtime.sinks import dispatch
    dispatch(
        [{"severity": "LOW", "ruleId": "r", "title": "t", "evidence": "e", "id": "s:1"}],
        [{"type": "sentinel", "name": "bad name"}, {"type": "file", "path": str(tmp_path / "out.log")}],
    )
    assert (tmp_path / "out.log").is_file()
    assert "sentinel config" in capsys.readouterr().err


def test_s_con_08_system_dispatch_stays_cheap(tmp_path, monkeypatch):
    _allow(monkeypatch, tmp_path)
    fake = FakeAzure()
    sink = sink_dict(fake, delivery="system", gzip=False)
    try:
        from prismor.runtime.sinks import dispatch
        dispatch([{"severity": "LOW", "ruleId": "r", "title": "t", "evidence": "e", "id": "warm:1"}], [sink])
        samples = []
        for n in range(200):
            started = time.perf_counter()
            dispatch([{"severity": "LOW", "ruleId": "r", "title": "t", "evidence": "e", "id": f"s:{n}"}], [sink])
            samples.append(time.perf_counter() - started)
    finally:
        fake.close()
    samples.sort()
    assert samples[int(len(samples) * 0.95)] < 0.020
    assert fake.requests == []


def test_s_cli_01_test_command(tmp_path, monkeypatch, capsys):
    _allow(monkeypatch, tmp_path)
    fake = FakeAzure(token="fixture-token")
    try:
        from prismor.runtime.sentinel.commands import run_test
        code = run_test(sink_dict(fake, gzip=False))
    finally:
        fake.close()
    out = capsys.readouterr().out
    assert code == 0
    assert "204" in out
    assert "PrismorAgentEvents_CL" in out
    assert "fixture-token" not in out


def test_s_cli_02_test_forbidden(tmp_path, monkeypatch, capsys):
    _allow(monkeypatch, tmp_path)
    fake = FakeAzure()
    fake.script("ingest", [(403, {}, b"")] * 4)
    try:
        from prismor.runtime.sentinel.commands import run_test
        code = run_test(sink_dict(fake, gzip=False, streams={"inventory": ""}))
    finally:
        fake.close()
    assert code == 4
    assert "Monitoring Metrics Publisher" in capsys.readouterr().err


def test_s_cli_03_status_json(tmp_path, monkeypatch, capsys):
    _allow(monkeypatch, tmp_path)
    fake = FakeAzure()
    try:
        from prismor.runtime.sentinel.commands import run_status
        code = run_status(sink_dict(fake), True)
    finally:
        fake.close()
    assert code == 0
    doc = json.loads(capsys.readouterr().out)
    for key in ("sink", "state", "streams", "token", "backoff_until", "version"):
        assert key in doc


def test_s_cli_04_schema_bicep_matches_files():
    from prismor.runtime.sentinel.commands import schema_text
    events = (ROOT / "packaging/sentinel/bicep/schema/agent_events.table.json").read_text(encoding="utf-8")
    inventory = (ROOT / "packaging/sentinel/bicep/schema/ai_inventory.table.json").read_text(encoding="utf-8")
    assert schema_text("events", "bicep") == events
    assert schema_text("inventory", "bicep") == inventory
