"""S-HTTP and S-AUTH-12/13: ingestion responses, retries, and the spool."""
from __future__ import annotations

import json
import uuid
from email.utils import formatdate

import pytest

from prismor.runtime.sentinel.auth import clear_cache
from prismor.runtime.sentinel.config import parse
from prismor.runtime.sentinel.delivery import flush_config
from prismor.runtime.sentinel.spool import Spool, spool_path
from tests.sentinel_fake import FakeAzure
from tests.sentinel_support import FakeClock, ingest_requests, sink_dict, token_requests


def setup_function():
    clear_cache()


def _allow(monkeypatch):
    monkeypatch.setenv("PRISMOR_SENTINEL_ALLOW_INSECURE_LOCALHOST", "1")


def _row(n=0):
    return {"EventId": f"evt_{n:032x}", "RuleId": "r", "EventTime": "2026-11-02T00:00:00Z"}


def _prepare(tmp_path, monkeypatch, fake, rows, **overrides):
    _allow(monkeypatch)
    monkeypatch.setenv("PRISMOR_HOME", str(tmp_path))
    cfg = parse(sink_dict(fake, **overrides))
    Spool(spool_path(cfg, "events")).append(rows, now=1)
    return cfg


def test_s_http_01_204(tmp_path, monkeypatch):
    fake = FakeAzure(token="fixture-token")
    try:
        cfg = _prepare(tmp_path, monkeypatch, fake, [_row()])
        summary = flush_config(cfg, clock=FakeClock(10), sleep=lambda _s: None, rand=lambda: 0)
    finally:
        fake.close()
    assert summary["state"] == "ok"
    posted = ingest_requests(fake)
    assert len(posted) == 1
    headers = {key.lower(): value for key, value in posted[0]["headers"].items()}
    assert headers["authorization"] == "Bearer fixture-token"
    assert headers["content-type"] == "application/json"
    uuid.UUID(headers["x-ms-client-request-id"])
    assert posted[0]["path"].endswith("/streams/Custom-PrismorAgentEvents")
    assert "api-version=2023-01-01" in posted[0]["query"]
    assert not (tmp_path / "sentinel-hmlr-sentinel-events.jsonl").read_text(encoding="utf-8").strip()


def test_s_http_02_retry_after_seconds(tmp_path, monkeypatch):
    fake = FakeAzure()
    fake.script("ingest", [(503, {"Retry-After": "7"}, b""), (204, {}, b"")])
    clock = FakeClock(100)
    try:
        cfg = _prepare(tmp_path, monkeypatch, fake, [_row()], delivery="background", gzip=False)
        flush_config(cfg, clock=clock, sleep=clock.sleep, rand=lambda: 0)
    finally:
        fake.close()
    assert len(ingest_requests(fake)) == 2
    assert clock.slept and 7 <= clock.slept[0] <= 8


def test_s_http_03_retry_after_http_date(tmp_path, monkeypatch):
    fake = FakeAzure()
    when = formatdate(1_700_000_000 + 30, usegmt=True)
    fake.script("ingest", [(429, {"Retry-After": when}, b""), (204, {}, b"")])
    clock = FakeClock(1_700_000_000)
    try:
        cfg = _prepare(tmp_path, monkeypatch, fake, [_row()], delivery="background")
        # The row's enqueue time has to sit inside the age window of this clock.
        Spool(spool_path(cfg, "events")).append([_row()], now=clock.now)
        flush_config(cfg, clock=clock, sleep=clock.sleep, rand=lambda: 0)
    finally:
        fake.close()
    assert clock.slept and abs(clock.slept[0] - 30) <= 1


def test_s_http_04_retry_after_clamped(tmp_path, monkeypatch):
    fake = FakeAzure()
    fake.script("ingest", [(429, {"Retry-After": "100000"}, b""), (204, {}, b"")])
    clock = FakeClock(0)
    try:
        cfg = _prepare(tmp_path, monkeypatch, fake, [_row()], delivery="background")
        flush_config(cfg, clock=clock, sleep=clock.sleep, rand=lambda: 0)
    finally:
        fake.close()
    assert clock.slept and abs(clock.slept[0] - 300) <= 1


def test_s_http_05_five_hundreds(tmp_path, monkeypatch):
    fake = FakeAzure()
    fake.script("ingest", [(500, {}, b"")] * 5)
    clock = FakeClock(0)
    sleeps = []

    def rand():
        return 0.5

    try:
        cfg = _prepare(tmp_path, monkeypatch, fake, [_row()], delivery="background", max_attempts=5)
        summary = flush_config(cfg, clock=clock, sleep=lambda s: sleeps.append(s), rand=rand)
    finally:
        fake.close()
    assert len(ingest_requests(fake)) == 5
    # attempt indexes 0..3 sleep rand()*min(60, 2**i) = 0.5, 1, 2, 4
    assert sleeps == [0.5, 1.0, 2.0, 4.0]
    health = json.loads((tmp_path / "sentinel-hmlr-sentinel-health.json").read_text(encoding="utf-8"))
    assert health["streams"]["events"]["last_error"]["status"] == 500
    assert summary["streams"]["events"]["pending"] == 1


def test_s_http_06_inline_backoff_skips_network(tmp_path, monkeypatch):
    _allow(monkeypatch)
    monkeypatch.setenv("PRISMOR_HOME", str(tmp_path))
    calls = {"n": 0}

    def transport(method, url, headers, body, timeout):
        calls["n"] += 1
        if "oauth2" in url:
            return 200, {}, json.dumps({"access_token": "access-token-value", "expires_in": 3600}).encode()
        raise ConnectionRefusedError("refused")

    fake = FakeAzure()
    try:
        cfg = parse(sink_dict(fake, timeout_seconds=1))
        Spool(spool_path(cfg, "events")).append([_row()], now=1)
        clock = FakeClock(50)
        first = flush_config(cfg, clock=clock, sleep=clock.sleep, rand=lambda: 0, transport=transport)
        after = calls["n"]
        second = flush_config(cfg, clock=clock, sleep=clock.sleep, rand=lambda: 0, transport=transport)
    finally:
        fake.close()
    assert first["streams"]["events"]["stop"] in {"retry", "budget"}
    assert clock.slept == []
    health = json.loads((tmp_path / "sentinel-hmlr-sentinel-health.json").read_text(encoding="utf-8"))
    assert health["backoff_until"]
    assert second.get("skipped") == "backoff"
    assert calls["n"] == after


def test_s_http_07_poison_bisect(tmp_path, monkeypatch):
    fake = FakeAzure()
    fake.poison = lambda row: row.get("EventId", "").endswith("3")
    rows = [_row(n) for n in range(8)]
    try:
        cfg = _prepare(tmp_path, monkeypatch, fake, rows, max_batch_records=100)
        flush_config(cfg, clock=FakeClock(10), sleep=lambda _s: None, rand=lambda: 0)
    finally:
        fake.close()
    assert len(ingest_requests(fake)) <= 7
    rejected = (tmp_path / "sentinel-hmlr-sentinel-events.rejected.jsonl").read_text(encoding="utf-8")
    assert _row(3)["EventId"] in rejected
    left = (tmp_path / "sentinel-hmlr-sentinel-events.jsonl").read_text(encoding="utf-8")
    assert _row(3)["EventId"] not in left
    for n in range(8):
        if n != 3:
            assert _row(n)["EventId"] not in left


def test_s_http_08_schema_error_keeps_rows(tmp_path, monkeypatch):
    fake = FakeAzure()
    fake.poison = lambda row: True
    rows = [_row(n) for n in range(4)]
    clock = FakeClock(20)
    try:
        cfg = _prepare(tmp_path, monkeypatch, fake, rows, max_batch_records=100)
        summary = flush_config(cfg, clock=clock, sleep=lambda _s: None, rand=lambda: 0)
    finally:
        fake.close()
    assert summary["state"] == "schema_error"
    spool = (tmp_path / "sentinel-hmlr-sentinel-events.jsonl").read_text(encoding="utf-8")
    for n in range(4):
        assert _row(n)["EventId"] in spool
    assert not (tmp_path / "sentinel-hmlr-sentinel-events.rejected.jsonl").exists()
    health = json.loads((tmp_path / "sentinel-hmlr-sentinel-health.json").read_text(encoding="utf-8"))
    assert health["backoff_until"] == 20 + 900


def test_s_http_09_forbidden(tmp_path, monkeypatch):
    fake = FakeAzure()
    fake.script("ingest", [(403, {"x-ms-error-code": "Forbidden"}, b"")] * 3)
    clock = FakeClock(5)
    try:
        cfg = _prepare(tmp_path, monkeypatch, fake, [_row()])
        summary = flush_config(cfg, clock=clock, sleep=lambda _s: None, rand=lambda: 0)
    finally:
        fake.close()
    assert summary["state"] == "forbidden"
    health = json.loads((tmp_path / "sentinel-hmlr-sentinel-health.json").read_text(encoding="utf-8"))
    assert health["backoff_until"] == 5 + 900
    assert "evt_" in (tmp_path / "sentinel-hmlr-sentinel-events.jsonl").read_text(encoding="utf-8")


def test_s_http_10_not_found(tmp_path, monkeypatch):
    fake = FakeAzure()
    fake.script("ingest", [(404, {}, b"")])
    try:
        cfg = _prepare(tmp_path, monkeypatch, fake, [_row()])
        summary = flush_config(cfg, clock=FakeClock(1), sleep=lambda _s: None, rand=lambda: 0)
    finally:
        fake.close()
    assert summary["state"] == "not_found"


def test_s_http_11_payload_too_large_splits(tmp_path, monkeypatch):
    fake = FakeAzure()
    fake.script("ingest", [(413, {}, b""), (204, {}, b""), (204, {}, b"")])
    rows = [_row(n) for n in range(4)]
    try:
        cfg = _prepare(tmp_path, monkeypatch, fake, rows, max_batch_records=100)
        flush_config(cfg, clock=FakeClock(1), sleep=lambda _s: None, rand=lambda: 0)
    finally:
        fake.close()
    assert len(ingest_requests(fake)) == 3
    assert not (tmp_path / "sentinel-hmlr-sentinel-events.jsonl").read_text(encoding="utf-8").strip()


def test_s_http_12_inline_budget(tmp_path, monkeypatch):
    import time
    _allow(monkeypatch)
    monkeypatch.setenv("PRISMOR_HOME", str(tmp_path))
    fake = FakeAzure()
    fake.delay = 5
    try:
        cfg = parse(sink_dict(fake, timeout_seconds=2, inline_budget_seconds=2, gzip=False))
        Spool(spool_path(cfg, "events")).append([_row()], now=__import__("time").time())
        started = time.monotonic()
        summary = flush_config(cfg, budget_s=2.0)
        elapsed = time.monotonic() - started
    finally:
        fake.close()
    assert elapsed <= 2.2
    assert summary["streams"]["events"]["pending"] == 1
    health = json.loads((tmp_path / "sentinel-hmlr-sentinel-health.json").read_text(encoding="utf-8"))
    assert health["streams"]["events"]["inline_budget_exhausted"] == 1


def test_s_http_13_error_code_header(tmp_path, monkeypatch):
    fake = FakeAzure()
    fake.script("ingest", [(500, {"x-ms-error-code": "ServerBusy"}, b"")])
    try:
        cfg = _prepare(tmp_path, monkeypatch, fake, [_row()])
        flush_config(cfg, clock=FakeClock(1), sleep=lambda _s: None, rand=lambda: 0)
    finally:
        fake.close()
    health = json.loads((tmp_path / "sentinel-hmlr-sentinel-health.json").read_text(encoding="utf-8"))
    assert health["streams"]["events"]["last_error"]["code"] == "ServerBusy"


def test_s_auth_12_refresh_on_401(tmp_path, monkeypatch):
    fake = FakeAzure(token="fixture-token")
    fake.script("ingest", [(401, {}, b""), (204, {}, b"")])
    try:
        cfg = _prepare(tmp_path, monkeypatch, fake, [_row()])
        flush_config(cfg, clock=FakeClock(1), sleep=lambda _s: None, rand=lambda: 0)
    finally:
        fake.close()
    assert len(token_requests(fake)) == 2
    assert len(ingest_requests(fake)) == 2
    assert not (tmp_path / "sentinel-hmlr-sentinel-events.jsonl").read_text(encoding="utf-8").strip()


def test_s_auth_13_second_401_keeps_rows(tmp_path, monkeypatch):
    fake = FakeAzure()
    fake.script("ingest", [(401, {}, b""), (401, {}, b"")])
    clock = FakeClock(10)
    try:
        cfg = _prepare(tmp_path, monkeypatch, fake, [_row()])
        summary = flush_config(cfg, clock=clock, sleep=lambda _s: None, rand=lambda: 0)
    finally:
        fake.close()
    assert summary["state"] == "auth_error"
    assert (tmp_path / "sentinel-hmlr-sentinel-events.jsonl").read_text(encoding="utf-8").strip()
    health = json.loads((tmp_path / "sentinel-hmlr-sentinel-health.json").read_text(encoding="utf-8"))
    assert health["backoff_until"] == 10 + 900


def test_s_spl_07_replay_twelve_hundred(tmp_path, monkeypatch):
    fake = FakeAzure()
    fake.script("ingest", [(503, {"Retry-After": "0"}, b"")])
    rows = [_row(n) for n in range(1200)]
    clock = FakeClock(0)
    try:
        cfg = _prepare(tmp_path, monkeypatch, fake, rows, delivery="background",
                       max_batch_records=500, gzip=False)
        flush_config(cfg, clock=clock, sleep=clock.sleep, rand=lambda: 0)
    finally:
        fake.close()
    posted = [item for item in ingest_requests(fake) if item.get("status") == 204]
    assert len(posted) >= 3
    delivered = []
    for item in posted:
        delivered.extend(json.loads(item["body"].decode("utf-8")))
    ids = [row["EventId"] for row in delivered]
    assert ids == [row["EventId"] for row in rows]
    assert len(ids) == len(set(ids)) == 1200
    assert not (tmp_path / "sentinel-hmlr-sentinel-events.jsonl").read_text(encoding="utf-8").strip()
