"""S-SPL: spool peek/ack, caps, and the single-flusher lock."""
from __future__ import annotations

import json

from prismor.runtime.sentinel.spool import Spool


def _spool(tmp_path, **kwargs):
    return Spool(tmp_path / "sentinel-hmlr-events.jsonl", max_records=kwargs.get("max_records", 100),
                 max_bytes=kwargs.get("max_bytes", 1_000_000), max_age_hours=kwargs.get("max_age_hours", 168))


def test_s_spl_01_append_peek_ack(tmp_path):
    spool = _spool(tmp_path)
    spool.append([{"EventId": "a"}, {"EventId": "b"}, {"EventId": "c"}], now=1)
    rows, token = spool.peek(10_000, 2)
    assert [row["EventId"] for row in rows] == ["a", "b"]
    assert spool.ack(token)
    left, _token = spool.peek(10_000, 10)
    assert [row["EventId"] for row in left] == ["c"]


def test_s_spl_02_crash_before_ack(tmp_path):
    spool = _spool(tmp_path)
    spool.append([{"EventId": "a"}], now=1)
    rows, _token = spool.peek(10_000, 10)
    assert rows[0]["EventId"] == "a"
    again, _token = spool.peek(10_000, 10)
    assert again[0]["EventId"] == "a"


def test_s_spl_03_ack_detects_rewrite(tmp_path):
    spool = _spool(tmp_path)
    spool.append([{"EventId": "a"}, {"EventId": "b"}], now=1)
    _rows, token = spool.peek(10_000, 1)
    spool.append([{"EventId": "c"}], now=2)
    # Rewrite the file so the first line changes, then ack must no-op.
    path = spool.path
    lines = path.read_text(encoding="utf-8").splitlines()
    path.write_text(lines[1] + "\n" + lines[0] + "\n" + lines[2] + "\n", encoding="utf-8")
    assert spool.ack(token) is False
    text = path.read_text(encoding="utf-8")
    assert "c" in text and "a" in text and "b" in text


def test_s_spl_04_torn_last_line(tmp_path):
    spool = _spool(tmp_path)
    good = json.dumps({"q": 1, "r": {"EventId": "a"}}) + "\n"
    spool.path.write_text(good + "{\"q\":2,\"r\":", encoding="utf-8")
    rows, _token = spool.peek(10_000, 10)
    assert [row["EventId"] for row in rows] == ["a"]


def test_s_spl_05_overflow_drops_oldest(tmp_path):
    spool = _spool(tmp_path, max_records=2)
    spool.append([{"EventId": "a"}, {"EventId": "b"}, {"EventId": "c"}], now=1)
    rows, _token = spool.peek(10_000, 10)
    assert [row["EventId"] for row in rows] == ["b", "c"]
    assert spool.dropped["overflow"] == 1


def test_s_spl_06_age_out(tmp_path):
    spool = _spool(tmp_path, max_age_hours=1)
    spool.append([{"EventId": "old"}], now=0)
    spool.append([{"EventId": "new"}], now=10_000)
    assert spool.age_out(10_000) == 1
    rows, _token = spool.peek(10_000, 10)
    assert [row["EventId"] for row in rows] == ["new"]


def test_s_spl_08_single_flusher(tmp_path):
    from prismor.runtime.sentinel.delivery import _try_lock
    path = tmp_path / "flush.lock"
    first = _try_lock(path)
    assert next(first) is True
    second = _try_lock(path)
    assert next(second) is False
    first.close()
    third = _try_lock(path)
    assert next(third) is True
    third.close()
