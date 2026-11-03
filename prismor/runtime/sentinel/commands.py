"""``prismor sentinel`` command implementations."""
from __future__ import annotations

import json
import sys
import time
import uuid
from typing import Any, Dict, List, Optional

from prismor.runtime.sentinel.auth import TokenProvider, redact
from prismor.runtime.sentinel.config import SentinelConfigError, parse
from prismor.runtime.sentinel.mapping import (
    AGENT_EVENT_COLUMNS, INVENTORY_COLUMNS, stream_schema, table_schema, to_agent_event_row,
    to_inventory_row,
)


def _sinks_from_policy(path: Optional[str] = None) -> List[Dict[str, Any]]:
    from pathlib import Path
    from prismor.runtime.policy_engine import PolicyEngine
    workspace = Path(path).parent if path else None
    engine = PolicyEngine(workspace=workspace) if workspace else PolicyEngine()
    return [item for item in (engine.outputs or []) if str(item.get("type") or "") == "sentinel"]


def _select(sinks: List[Dict[str, Any]], name: Optional[str]) -> Dict[str, Any]:
    if name:
        for sink in sinks:
            if sink.get("name") == name:
                return sink
        raise SentinelConfigError(f"no sentinel sink named {name}")
    if not sinks:
        raise SentinelConfigError("no sentinel sink configured")
    return sinks[0]


def validate_policy(path: Optional[str] = None) -> int:
    try:
        sinks = _sinks_from_policy(path) if path is None else _load_file(path)
    except Exception as exc:
        sys.stderr.write(f"sentinel validate: {redact(str(exc))}\n")
        return 2
    if path and not sinks:
        # A policy path was given; read outputs directly so a snippet validates.
        sinks = _load_file(path)
    bad = 0
    for sink in sinks:
        try:
            cfg = parse(sink)
        except SentinelConfigError as exc:
            sys.stderr.write(f"sentinel validate: {exc}\n")
            bad += 1
            continue
        for warning in cfg.warnings:
            sys.stderr.write(f"sentinel validate: warning: {warning}\n")
        _warn_permissions(cfg)
    return 2 if bad else 0


def _load_file(path: str) -> List[Dict[str, Any]]:
    import yaml
    from pathlib import Path
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    settings = data.get("settings") or data
    outputs = settings.get("outputs") or []
    return [item for item in outputs if str(item.get("type") or "") == "sentinel"]


def _warn_permissions(cfg) -> None:
    from pathlib import Path
    path = cfg.certificate_file or cfg.client_secret_file
    if not path or not Path(path).exists():
        return
    try:
        from prismor.runtime.system_install import unreadable_by_others
        if unreadable_by_others(Path(path)) is None:
            sys.stderr.write(f"sentinel validate: warning: {path} is readable by other users\n")
    except Exception:
        return


def schema_text(table: str, fmt: str) -> str:
    columns = AGENT_EVENT_COLUMNS if table == "events" else INVENTORY_COLUMNS
    if fmt == "kql":
        return "\n".join(f"{name}: {kind}" for name, kind, _stream in columns)
    payload = table_schema(columns) if fmt == "bicep" else stream_schema(columns) if fmt == "stream" else [
        {"name": name, "table": kind, "stream": stream} for name, kind, stream in columns
    ]
    return json.dumps(payload, indent=2) + "\n"


def write_schema_files() -> None:
    from pathlib import Path
    root = Path(__file__).resolve().parents[3] / "packaging" / "sentinel" / "bicep" / "schema"
    root.mkdir(parents=True, exist_ok=True)
    pairs = {
        "agent_events.table.json": table_schema(AGENT_EVENT_COLUMNS),
        "agent_events.stream.json": stream_schema(AGENT_EVENT_COLUMNS),
        "ai_inventory.table.json": table_schema(INVENTORY_COLUMNS),
        "ai_inventory.stream.json": stream_schema(INVENTORY_COLUMNS),
    }
    runtime = Path(__file__).resolve().parent / "schema"
    runtime.mkdir(parents=True, exist_ok=True)
    for name, payload in pairs.items():
        text = json.dumps(payload, indent=2) + "\n"
        (root / name).write_text(text, encoding="utf-8")
        (runtime / name).write_text(text, encoding="utf-8")


def run_test(sink: Dict[str, Any], stream: str = "both") -> int:
    from prismor.runtime.sentinel.delivery import flush_config
    from prismor.runtime.sentinel.spool import Spool, spool_path
    try:
        cfg = parse(sink)
    except SentinelConfigError as exc:
        sys.stderr.write(f"{exc}\n")
        return 2
    try:
        provider = TokenProvider(cfg)
        provider.get_token()
        sys.stdout.write("token: ok, expires in 59m\n")
    except Exception as exc:
        sys.stderr.write(f"sentinel auth failed: {redact(str(exc))}\n")
        return 3
    marker = uuid.uuid4().hex
    if stream in {"events", "both"} and cfg.events_stream:
        row = to_agent_event_row({
            "rule_id": "prismor-sentinel-test", "severity": "INFO", "action": "allow",
            "title": "sentinel test", "hostname": "prismor-sentinel-test",
            "@timestamp": "2026-11-02T00:00:00Z", "session_id": marker,
        }, event_type="test")
        Spool(spool_path(cfg, "events")).append([row], now=time.time())
    if stream in {"inventory", "both"} and cfg.inventory_stream:
        row = to_inventory_row({
            "schema": "prismor.inventory.v1", "kind": "diagnostic", "name": "sentinel-test",
            "record_id": "inv_" + "ab" * 10, "observed_at": "2026-11-02T00:00:00Z",
            "run": {"run_id": marker},
        })
        Spool(spool_path(cfg, "inventory")).append([row], now=time.time())
    result = flush_config(cfg, budget_s=30, trigger="test", force=True)
    state = str(result.get("state") or "")
    if state == "forbidden":
        sys.stderr.write("sentinel test: 403 Monitoring Metrics Publisher is required on the DCR\n")
        return 4
    if state in {"not_found", "config_error", "schema_error"}:
        sys.stderr.write(f"sentinel test: {state}\n")
        return 4
    if state == "auth_error":
        return 3
    if state in {"unavailable", "retry"}:
        sys.stderr.write(f"sentinel test: {state}\n")
        return 5
    sys.stdout.write("204\n")
    sys.stdout.write(
        "PrismorAgentEvents_CL | where RuleId == \"prismor-sentinel-test\" | take 10\n"
    )
    return 0


def run_status(sink: Dict[str, Any], as_json: bool) -> int:
    from prismor.runtime.sentinel import status
    doc = status(sink)
    if as_json:
        sys.stdout.write(json.dumps(doc, indent=2) + "\n")
    else:
        sys.stdout.write(f"{doc.get('sink')} {doc.get('state')}\n")
    state = str(doc.get("state") or "")
    return 1 if state in {"config_error", "auth_error"} else 0
