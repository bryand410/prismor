"""S-BAT: batch sizing and gzip."""
from __future__ import annotations

import gzip
import json

from prismor.runtime.sentinel.batcher import array_size, gzip_body, iter_batches, prepare_rows, row_bytes


def _row(name: str, pad: int = 0) -> dict:
    return {"Name": name, "Pad": "x" * pad}


def test_s_bat_01_empty():
    assert list(iter_batches([], 1000, 10)) == []


def test_s_bat_02_one_row():
    batch = list(iter_batches([{"Name": "a"}], 1000, 10))
    assert len(batch) == 1
    assert json.loads(batch[0].body.decode()) == [{"Name": "a"}]


def test_s_bat_03_exact_boundary():
    first = _row("a", 10)
    second = _row("b", 10)
    parts = [row_bytes(first), row_bytes(second)]
    cap = array_size(parts)
    batches = list(iter_batches([first, second], cap, 10))
    assert len(batches) == 1
    assert len(batches[0].body) == cap


def test_s_bat_04_one_byte_over():
    first = _row("a", 10)
    second = _row("b", 10)
    cap = array_size([row_bytes(first), row_bytes(second)]) - 1
    batches = list(iter_batches([first, second], cap, 10))
    assert len(batches) == 2
    assert all(len(batch.body) <= cap for batch in batches)
    assert [row["Name"] for batch in batches for row in batch.rows] == ["a", "b"]


def test_s_bat_05_record_cap():
    rows = [{"Name": str(i)} for i in range(1234)]
    batches = list(iter_batches(rows, 1_000_000, 500))
    assert [batch.count for batch in batches] == [500, 500, 234]


def test_s_bat_06_random_sizes():
    import random
    rng = random.Random(1)
    rows = [{"Name": "n" * rng.randint(1, 40), "i": i} for i in range(200)]
    batches = list(iter_batches(rows, 2000, 20))
    flat = [row["i"] for batch in batches for row in batch.rows]
    assert flat == list(range(200))
    for batch in batches:
        assert len(batch.body) <= 2000
        assert batch.count <= 20


def test_s_bat_07_oversize_quarantine():
    row = {"Evidence": "x" * 5000}
    sendable, quarantined = prepare_rows([row], 100)
    assert sendable == []
    assert quarantined == [row]
    assert list(iter_batches(quarantined, 100, 10)) == []


def test_s_bat_08_utf8_bytes():
    row = {"Name": "é" * 1000}
    assert len(row_bytes(row)) > 1000
    # 1000 times U+00E9 is 2000 bytes plus JSON overhead.
    assert "é" * 1000 in row_bytes(row).decode("utf-8")


def test_s_bat_09_gzip_deterministic():
    body = b'[{"Name":"a"}]'
    first = gzip_body(body)
    second = gzip_body(body)
    assert first == second
    assert gzip.decompress(first) == body


def test_s_bat_10_and_11_defaults():
    from prismor.runtime.sentinel.config import parse
    cfg = parse({
        "name": "hmlr-sentinel",
        "endpoint": "https://example.ingest.monitor.azure.com",
        "dcr_immutable_id": "dcr-" + "ab" * 16,
        "auth": {"mode": "managed_identity"},
        "gzip": False,
    })
    rows = [{"Name": "n" * 100} for _ in range(10)]
    for batch in iter_batches(rows, cfg.max_batch_bytes, cfg.max_batch_records):
        assert len(batch.body) < 1_000_000
        assert len(gzip_body(batch.body)) < 1_000_000
