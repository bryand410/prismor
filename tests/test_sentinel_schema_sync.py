"""S-SCH: mapping constants, schema JSON, and the DCR transform stay in lockstep."""
from __future__ import annotations

import json
import re
from pathlib import Path

from prismor.runtime.sentinel.mapping import (
    AGENT_EVENT_COLUMNS, INVENTORY_COLUMNS, stream_schema, table_schema,
)

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = ROOT / "packaging" / "sentinel" / "bicep" / "schema"
_RESERVED = {"TenantId", "Type", "Title", "id", "_ResourceId", "_SubscriptionId", "UniqueId"}


def _load(name):
    return json.loads((SCHEMA / name).read_text(encoding="utf-8"))


def test_s_sch_01_columns_match_mapping():
    assert _load("agent_events.table.json") == table_schema(AGENT_EVENT_COLUMNS)
    assert _load("agent_events.stream.json") == stream_schema(AGENT_EVENT_COLUMNS)
    assert _load("ai_inventory.table.json") == table_schema(INVENTORY_COLUMNS)
    assert _load("ai_inventory.stream.json") == stream_schema(INVENTORY_COLUMNS)


def test_s_sch_02_datetime_casing():
    for name in ("agent_events.table.json", "ai_inventory.table.json"):
        types = {item["name"]: item["type"] for item in _load(name)}
        assert types["TimeGenerated"] == "dateTime"
    for name in ("agent_events.stream.json", "ai_inventory.stream.json"):
        types = {item["name"]: item["type"] for item in _load(name)}
        assert "TimeGenerated" not in types
        assert "datetime" in types.values()
        assert "dateTime" not in types.values()


def test_s_sch_03_transform_reads_stream_columns():
    text = (ROOT / "packaging" / "sentinel" / "bicep" / "main.bicep").read_text(encoding="utf-8")
    stream = {item["name"] for item in _load("agent_events.stream.json")}
    stream |= {item["name"] for item in _load("ai_inventory.stream.json")}
    expressions = re.findall(r"transformKql: '([^']+)'", text)
    assert len(expressions) == 2
    for expr in expressions:
        used = re.findall(r"todatetime\((\w+)\)", expr)
        assert used
        assert set(used) <= stream


def test_s_sch_04_limits():
    text = (ROOT / "packaging" / "sentinel" / "bicep" / "main.bicep").read_text(encoding="utf-8")
    for expr in re.findall(r"transformKql: '([^']+)'", text):
        assert len(expr) <= 15360
    assert "PrismorAgentEvents_CL" in text and "PrismorAIInventory_CL" in text
    for table in ("agent_events.table.json", "ai_inventory.table.json"):
        columns = _load(table)
        assert len(columns) <= 500
        names = [item["name"] for item in columns]
        assert _RESERVED.isdisjoint(names)
        assert all(len(name) <= 45 for name in names)
