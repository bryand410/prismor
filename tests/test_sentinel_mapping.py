"""S-MAP: column mapping and golden files."""
from __future__ import annotations

import json
import os
import random
import re
from datetime import datetime, timezone
from pathlib import Path

import pytest

from prismor.runtime.sentinel.mapping import (
    AGENT_EVENT_COLUMNS, INVENTORY_COLUMNS, client_columns, dumps_row,
    event_id, to_agent_event_row, to_inventory_row,
)
from prismor.runtime.sinks import _build_event

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "sentinel_fixtures"
GOLDEN = ROOT / "tests" / "golden" / "sentinel"
_RESERVED = {"TenantId", "Type", "Title", "id", "_ResourceId", "_SubscriptionId", "UniqueId", "TimeGenerated"}
_NAME = re.compile(r"^[A-Za-z][A-Za-z0-9_]{0,44}$")


class _FrozenDateTime(datetime):
    @classmethod
    def now(cls, tz=None):
        return datetime(2026, 8, 30, 18, 4, 11, tzinfo=timezone.utc)


def _freeze(monkeypatch):
    import prismor.runtime.sinks as sinks
    monkeypatch.setattr(sinks, "datetime", _FrozenDateTime)
    monkeypatch.setattr(sinks, "_hostname", lambda: "laptop.local")
    monkeypatch.setattr(
        "prismor.runtime.enterprise.identity.load_identity",
        lambda: {"device_id": "device-fixture"},
    )


def _row_from_finding(name, monkeypatch):
    _freeze(monkeypatch)
    finding = json.loads((FIXTURES / name).read_text(encoding="utf-8"))
    return to_agent_event_row(_build_event(finding))


def _compare(name, row):
    GOLDEN.mkdir(parents=True, exist_ok=True)
    path = GOLDEN / name
    payload = dumps_row(row) + "\n"
    if os.environ.get("PRISMOR_UPDATE_GOLDENS") == "1":
        path.write_text(payload, encoding="utf-8")
    assert path.read_text(encoding="utf-8") == payload


def _assert_shape(row, columns):
    assert _RESERVED.isdisjoint(row)
    assert "TimeGenerated" not in row
    names = list(row)
    assert all(_NAME.match(name) for name in names)
    assert len(names) <= 500
    expected = [name for name in client_columns(columns) if name in row]
    assert names == expected


def test_s_map_01_block_golden(monkeypatch):
    row = _row_from_finding("finding_block.json", monkeypatch)
    _compare("agent_event_block.json", row)
    _assert_shape(row, AGENT_EVENT_COLUMNS)


def test_s_map_02_audit_golden(monkeypatch):
    row = _row_from_finding("finding_audit_allowed.json", monkeypatch)
    assert row["EventType"] == "audit"
    assert row["Action"] == "allow"
    assert row["Category"] == "audit"
    assert row["Severity"] == "INFO"
    _compare("agent_event_audit.json", row)


def test_s_map_03_additional_fields():
    row = to_agent_event_row({"rule_id": "r", "severity": "LOW", "foo": 1, "bar": {"x": 2},
                              "@timestamp": "2026-11-02T00:00:00Z"})
    assert row["AdditionalFields"]["foo"] == 1
    assert row["AdditionalFields"]["bar"] == {"x": 2}
    assert set(row).issubset(set(client_columns(AGENT_EVENT_COLUMNS)))


def test_s_map_04_and_05_reserved_and_order(monkeypatch):
    rows = [
        _row_from_finding("finding_block.json", monkeypatch),
        _row_from_finding("finding_audit_allowed.json", monkeypatch),
        to_inventory_row(json.loads((FIXTURES / "inventory_cps_agent.json").read_text(encoding="utf-8"))),
        to_inventory_row(json.loads((FIXTURES / "inventory_mcp_endpoint.json").read_text(encoding="utf-8"))),
    ]
    for row in rows:
        columns = AGENT_EVENT_COLUMNS if "EventId" in row else INVENTORY_COLUMNS
        _assert_shape(row, columns)


def test_s_map_06_event_id_stable():
    event = {"hostname": "h", "session_id": "s", "finding_id": "f", "rule_id": "r",
             "@timestamp": "2026-11-02T00:00:00Z"}
    first = event_id(event)
    assert first == event_id(dict(event))
    assert first != event_id({**event, "finding_id": "other"})
    assert re.fullmatch(r"evt_[0-9a-f]{32}", first)


def test_s_map_07_timestamp_normalisation():
    row = to_agent_event_row({"@timestamp": "2026-08-30T18:04:11+01:00", "rule_id": "r"}, now=1_700_000_000)
    assert row["EventTime"] == "2026-08-30T17:04:11Z"
    broken = to_agent_event_row({"@timestamp": "not-a-time", "rule_id": "r"}, now=1_700_000_000)
    assert broken["EventTime"] == "2023-11-14T22:13:20Z"
    assert broken["AdditionalFields"]["_time_fixed"] is True


def test_s_map_08_utf8_truncation():
    evidence = "あ" * 23334  # 3-byte characters, 70002 bytes
    row = to_agent_event_row({"rule_id": "r", "evidence": evidence, "@timestamp": "2026-11-02T00:00:00Z"})
    raw = row["Evidence"].encode("utf-8")
    assert len(raw) <= 16384
    row["Evidence"].encode("utf-8")  # still valid
    assert "…[truncated " in row["Evidence"] and row["Evidence"].endswith("bytes]")
    suffix = row["Evidence"][row["Evidence"].index("…[truncated "):]
    removed = int(suffix.split()[1])
    assert removed == len(evidence.encode("utf-8")) - (len(raw) - len(suffix.encode("utf-8")))


def test_s_map_09_dynamic_cap():
    row = to_agent_event_row({
        "rule_id": "r", "@timestamp": "2026-11-02T00:00:00Z",
        "blob": "x" * 100_000,
    })
    assert row["AdditionalFields"]["_truncated"] is True
    assert row["AdditionalFields"]["_bytes"] > 16 * 1024


def test_s_map_10_subject_modes():
    event = {"rule_id": "r", "subject": "Ada@Example.com", "@timestamp": "2026-11-02T00:00:00Z"}
    hashed = to_agent_event_row(event, subject_mode="hash", subject_salt="salt")
    import hashlib
    assert hashed["Subject"] == hashlib.sha256(b"saltada@example.com").hexdigest()[:32]
    assert to_agent_event_row(event, subject_mode="omit")["Subject"] == ""
    assert to_agent_event_row(event, subject_mode="plain")["Subject"] == "Ada@Example.com"


def test_s_map_11_evidence_omitted():
    row = to_agent_event_row({"rule_id": "r", "evidence": "secret-looking", "@timestamp": "2026-11-02T00:00:00Z"},
                             include_evidence=False)
    assert row["Evidence"] == ""


@pytest.mark.parametrize("severity,rank", [
    ("CRITICAL", 4), ("HIGH", 3), ("MEDIUM", 2), ("LOW", 1), ("INFO", 0), ("NOPE", 0),
])
def test_s_map_12_severity_rank(severity, rank):
    row = to_agent_event_row({"rule_id": "r", "severity": severity, "@timestamp": "2026-11-02T00:00:00Z"})
    assert row["SeverityRank"] == rank


def test_s_map_13_inventory_cps_golden():
    record = json.loads((FIXTURES / "inventory_cps_agent.json").read_text(encoding="utf-8"))
    row = to_inventory_row(record)
    assert row["EntraTenantId"] == "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
    assert row["RiskSignalIds"] == ["NO_AUTH", "SHARED_TENANT_WIDE"]
    assert row["InventorySource"] == "lowcode.copilot_studio"
    _compare("inventory_cps_agent.json", row)


def test_s_map_14_inventory_mcp_golden():
    record = json.loads((FIXTURES / "inventory_mcp_endpoint.json").read_text(encoding="utf-8"))
    row = to_inventory_row(record)
    assert row["Surface"] == "endpoint"
    assert row["HostId"] == "h_fixturehost0001"
    _compare("inventory_mcp_endpoint.json", row)


def test_s_map_15_missing_governance_omits_numbers():
    row = to_inventory_row({"kind": "agent", "name": "bare", "observed_at": "2026-11-02T00:00:00Z"})
    assert "Managed" not in row and "RiskScore" not in row and "Approved" not in row
    assert "None" not in json.dumps(row)


def test_s_map_16_mapping_never_raises():
    rng = random.Random(4)
    for _ in range(200):
        payload = {rng.choice(["rule_id", "foo", "@timestamp", "severity"]): rng.choice([None, 1, "x", {"a": 1}])
                   for _ in range(3)}
        row = to_agent_event_row(payload, now=1_700_000_000)
        assert isinstance(row, dict)
        _assert_shape(row, AGENT_EVENT_COLUMNS)


def test_s_map_17_scrub_known_shapes():
    aws = "AKIA" + "IOSFODNN7EXAMPLE"
    github = "ghp_" + "a" * 36
    row = to_agent_event_row({
        "rule_id": "r", "evidence": f"keys {aws} and {github}",
        "@timestamp": "2026-11-02T00:00:00Z",
    })
    blob = json.dumps(row)
    assert aws not in blob and github not in blob
