"""Map scrubbed Prismor events and inventory records onto Sentinel columns.

``AGENT_EVENT_COLUMNS`` and ``INVENTORY_COLUMNS`` are the source of truth for
the Bicep schema files and the KQL lint. ``TimeGenerated`` is set by the DCR,
not by the client.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Sequence, Tuple

SCHEMA_EVENTS = "prismor.agent_events.v1"
SCHEMA_INVENTORY = "prismor.inventory.v1"

# (name, table type, stream type or None when the client must not send it)
AGENT_EVENT_COLUMNS: List[Tuple[str, str, Optional[str]]] = [
    ("TimeGenerated", "dateTime", None),
    ("EventTime", "dateTime", "datetime"),
    ("EventId", "string", "string"),
    ("SchemaVersion", "string", "string"),
    ("EventType", "string", "string"),
    ("Source", "string", "string"),
    ("PrismorVersion", "string", "string"),
    ("Hostname", "string", "string"),
    ("DeviceId", "string", "string"),
    ("Subject", "string", "string"),
    ("SessionId", "string", "string"),
    ("SessionSeq", "long", "long"),
    ("FindingId", "string", "string"),
    ("RuleId", "string", "string"),
    ("Category", "string", "string"),
    ("Severity", "string", "string"),
    ("SeverityRank", "int", "int"),
    ("Action", "string", "string"),
    ("FindingTitle", "string", "string"),
    ("Evidence", "string", "string"),
    ("Agent", "string", "string"),
    ("AgentName", "string", "string"),
    ("Mode", "string", "string"),
    ("Workspace", "string", "string"),
    ("Repo", "string", "string"),
    ("PolicyScope", "string", "string"),
    ("EvalMs", "real", "real"),
    ("Environment", "string", "string"),
    ("Release", "string", "string"),
    ("AdditionalFields", "dynamic", "dynamic"),
]

INVENTORY_COLUMNS: List[Tuple[str, str, Optional[str]]] = [
    ("TimeGenerated", "dateTime", None),
    ("ObservedAt", "dateTime", "datetime"),
    ("RecordId", "string", "string"),
    ("EntityKey", "string", "string"),
    ("GroupId", "string", "string"),
    ("SchemaVersion", "string", "string"),
    ("Kind", "string", "string"),
    ("Surface", "string", "string"),
    ("InventorySource", "string", "string"),
    ("Product", "string", "string"),
    ("Vendor", "string", "string"),
    ("Name", "string", "string"),
    ("Version", "string", "string"),
    ("HostId", "string", "string"),
    ("Hostname", "string", "string"),
    ("OsName", "string", "string"),
    ("UserHash", "string", "string"),
    ("Path", "string", "string"),
    ("Scope", "string", "string"),
    ("RepoName", "string", "string"),
    ("EntraTenantId", "string", "string"),
    ("PowerPlatformEnvironmentId", "string", "string"),
    ("CloudAccount", "string", "string"),
    ("Region", "string", "string"),
    ("Namespace", "string", "string"),
    ("Location", "dynamic", "dynamic"),
    ("Managed", "boolean", "boolean"),
    ("GovernedBy", "string", "string"),
    ("Coverable", "boolean", "boolean"),
    ("GovernanceMode", "string", "string"),
    ("Approved", "boolean", "boolean"),
    ("RiskScore", "int", "int"),
    ("RiskLevel", "string", "string"),
    ("RiskSignalIds", "dynamic", "dynamic"),
    ("RiskSignals", "dynamic", "dynamic"),
    ("Attributes", "dynamic", "dynamic"),
    ("Evidence", "dynamic", "dynamic"),
    ("Related", "dynamic", "dynamic"),
    ("RunId", "string", "string"),
    ("ScannerVersion", "string", "string"),
    ("CollectorVersion", "string", "string"),
]

_STRING_CAP = 32 * 1024
_EVIDENCE_CAP = 16 * 1024
_DYNAMIC_CAP = 16 * 1024
_ATTR_CAP = 32 * 1024
_SEVERITY_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
_EVENT_STRINGS = {
    "EventTime", "EventId", "SchemaVersion", "EventType", "Source", "PrismorVersion",
    "Hostname", "DeviceId", "Subject", "SessionId", "FindingId", "RuleId", "Category",
    "Severity", "Action", "FindingTitle", "Evidence", "Agent", "AgentName", "Mode",
    "Workspace", "Repo", "PolicyScope", "Environment", "Release",
}
_MAPPED_EVENT_KEYS = {
    "@timestamp", "hostname", "severity", "category", "ruleid", "rule_id", "action",
    "title", "evidence", "session_id", "finding_id", "id", "subject", "session_seq",
    "agent", "agent_name", "mode", "workspace", "repo", "policy_scope", "eval_ms",
    "environment", "release", "source", "event_type", "_origin", "_time_fixed",
}


def client_columns(columns: Sequence[Tuple[str, str, Optional[str]]]) -> List[str]:
    return [name for name, _table, stream in columns if stream]


def table_schema(columns: Sequence[Tuple[str, str, Optional[str]]]) -> List[Dict[str, str]]:
    return [{"name": name, "type": table} for name, table, _stream in columns]


def stream_schema(columns: Sequence[Tuple[str, str, Optional[str]]]) -> List[Dict[str, str]]:
    return [{"name": name, "type": stream} for name, _table, stream in columns if stream]


def _now_iso(now: Optional[float] = None) -> str:
    import time
    stamp = time.time() if now is None else now
    moment = datetime.fromtimestamp(stamp, timezone.utc)
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


def _normalise_time(value: Any, *, now: Optional[float], fixed: Dict[str, Any]) -> str:
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return _now_iso(float(value))
    text = str(value or "").strip()
    if not text:
        fixed["_time_fixed"] = True
        return _now_iso(now)
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        fixed["_time_fixed"] = True
        return _now_iso(now)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    parsed = parsed.astimezone(timezone.utc).replace(microsecond=0)
    return parsed.strftime("%Y-%m-%dT%H:%M:%SZ")


def _truncate(text: str, limit: int) -> str:
    """Shorten ``text`` to ``limit`` UTF-8 bytes without splitting a code point."""
    raw = text.encode("utf-8")
    if len(raw) <= limit:
        return text
    best = ""
    lo, hi = 0, len(text)
    while lo <= hi:
        mid = (lo + hi) // 2
        body = text[:mid]
        removed = len(raw) - len(body.encode("utf-8"))
        suffix = f"…[truncated {removed} bytes]"
        encoded = len((body + suffix).encode("utf-8"))
        if encoded <= limit:
            best = body + suffix
            lo = mid + 1
        else:
            hi = mid - 1
    return best


def _scrub(value: str) -> str:
    try:
        from prismor.runtime.sinks import _scrub_for_sink
        return str(_scrub_for_sink(value))
    except Exception:
        return value


def _cap_dynamic(value: Any, limit: int) -> Any:
    try:
        encoded = json.dumps(value, ensure_ascii=False, separators=(",", ":"), default=str).encode("utf-8")
    except (TypeError, ValueError):
        encoded = b"{}"
    if len(encoded) <= limit:
        return value
    return {"_truncated": True, "_bytes": len(encoded)}


def event_id(event: Dict[str, Any]) -> str:
    raw = "|".join([
        str(event.get("hostname") or ""),
        str(event.get("session_id") or ""),
        str(event.get("finding_id") or ""),
        str(event.get("rule_id") or event.get("ruleId") or ""),
        str(event.get("@timestamp") or ""),
    ])
    return "evt_" + hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]


def _rank(severity: str) -> int:
    return _SEVERITY_RANK.get(severity.upper(), 0)


def _subject(value: str, mode: str, salt: str) -> str:
    if mode == "omit":
        return ""
    if mode == "hash":
        return hashlib.sha256((salt + value.lower()).encode("utf-8")).hexdigest()[:32]
    return value


def _device_id() -> str:
    # Verified against enterprise/identity.py: load_identity() stores device_id.
    try:
        from prismor.runtime.enterprise import identity
        loaded = identity.load_identity() or {}
        return str(loaded.get("device_id") or "")
    except Exception:
        return ""


def _version() -> str:
    try:
        from prismor.runtime import __version__
        return __version__
    except Exception:
        return ""


def _ordered(row: Dict[str, Any], columns: Sequence[Tuple[str, str, Optional[str]]]) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    for name, _table, stream in columns:
        if stream and name in row:
            out[name] = row[name]
    return out


def to_agent_event_row(event: Dict[str, Any], *, subject_mode: str = "plain", subject_salt: str = "",
                       include_evidence: bool = True, now: Optional[float] = None,
                       event_type: str = "") -> Dict[str, Any]:
    """Total mapping. Never raises; a failure becomes a mapping-error row."""
    try:
        return _agent_row(event, subject_mode=subject_mode, subject_salt=subject_salt,
                          include_evidence=include_evidence, now=now, event_type=event_type)
    except Exception:
        return _ordered({
            "EventTime": _now_iso(now),
            "EventId": "evt_" + "0" * 32,
            "SchemaVersion": SCHEMA_EVENTS,
            "EventType": "finding",
            "RuleId": "prismor-sentinel-mapping-error",
            "Severity": "INFO",
            "SeverityRank": 0,
            "Source": "prismor",
            "PrismorVersion": _version(),
        }, AGENT_EVENT_COLUMNS)


def _agent_row(event: Dict[str, Any], *, subject_mode: str, subject_salt: str,
               include_evidence: bool, now: Optional[float], event_type: str) -> Dict[str, Any]:
    fixed: Dict[str, Any] = {}
    rule = str(event.get("rule_id") or event.get("ruleId") or "")
    kind = event_type or str(event.get("event_type") or "")
    if not kind:
        if rule == "audit-allowed":
            kind = "audit"
        elif event.get("_origin") == "judge":
            kind = "judge"
        elif rule == "prismor-sentinel-test":
            kind = "test"
        elif rule == "prismor-sentinel-heartbeat":
            kind = "health"
        else:
            kind = "finding"
    severity = str(event.get("severity") or ("INFO" if kind == "audit" else "")).upper()
    evidence = ""
    if include_evidence:
        evidence = _truncate(_scrub(str(event.get("evidence") or "")), _EVIDENCE_CAP)
    extra: Dict[str, Any] = {}
    for key, value in event.items():
        if str(key).lower() in _MAPPED_EVENT_KEYS or str(key).startswith("_"):
            continue
        extra[str(key)] = value
    if fixed.get("_time_fixed"):
        extra["_time_fixed"] = True
    when = _normalise_time(event.get("@timestamp"), now=now, fixed=fixed)
    if fixed.get("_time_fixed"):
        extra["_time_fixed"] = True
    additional = _cap_dynamic(extra, _DYNAMIC_CAP) if extra else {}
    seq = event.get("session_seq")
    eval_ms = event.get("eval_ms")
    row: Dict[str, Any] = {
        "EventTime": when,
        "EventId": event_id({**event, "@timestamp": event.get("@timestamp") or when, "rule_id": rule}),
        "SchemaVersion": SCHEMA_EVENTS,
        "EventType": kind,
        "Source": str(event.get("source") or "prismor"),
        "PrismorVersion": _version(),
        "Hostname": str(event.get("hostname") or ""),
        "DeviceId": _device_id(),
        "Subject": _subject(str(event.get("subject") or ""), subject_mode, subject_salt),
        "SessionId": str(event.get("session_id") or ""),
        "FindingId": str(event.get("finding_id") or ""),
        "RuleId": rule,
        "Category": str(event.get("category") or ("audit" if kind == "audit" else "")),
        "Severity": severity,
        "SeverityRank": _rank(severity),
        "Action": str(event.get("action") or ("allow" if kind == "audit" else "")),
        "FindingTitle": _truncate(_scrub(str(event.get("title") or "")), _STRING_CAP),
        "Evidence": evidence,
        "Agent": str(event.get("agent") or ""),
        "AgentName": str(event.get("agent_name") or ""),
        "Mode": str(event.get("mode") or ""),
        "Workspace": str(event.get("workspace") or ""),
        "Repo": str(event.get("repo") or ""),
        "PolicyScope": str(event.get("policy_scope") or ""),
        "Environment": str(event.get("environment") or ""),
        "Release": str(event.get("release") or ""),
    }
    if seq is not None and seq != "":
        try:
            row["SessionSeq"] = int(seq)
        except (TypeError, ValueError):
            pass
    if eval_ms is not None and eval_ms != "":
        try:
            row["EvalMs"] = float(eval_ms)
        except (TypeError, ValueError):
            pass
    if additional:
        row["AdditionalFields"] = additional
    return _ordered(row, AGENT_EVENT_COLUMNS)


def to_inventory_row(record: Dict[str, Any], *, now: Optional[float] = None) -> Dict[str, Any]:
    try:
        return _inventory_row(record, now=now)
    except Exception:
        return _ordered({
            "ObservedAt": _now_iso(now),
            "RecordId": str((record or {}).get("record_id") or ""),
            "SchemaVersion": SCHEMA_INVENTORY,
            "Kind": "diagnostic",
            "Name": "mapping-error",
        }, INVENTORY_COLUMNS)


def _inventory_row(record: Dict[str, Any], *, now: Optional[float]) -> Dict[str, Any]:
    record = record or {}
    location = record.get("location") if isinstance(record.get("location"), dict) else {}
    governance = record.get("governance") if isinstance(record.get("governance"), dict) else {}
    risk = record.get("risk") if isinstance(record.get("risk"), dict) else {}
    run = record.get("run") if isinstance(record.get("run"), dict) else {}
    fixed: Dict[str, Any] = {}
    signals = risk.get("signals") if isinstance(risk.get("signals"), list) else []
    signal_ids = [str(item.get("id")) for item in signals if isinstance(item, dict) and item.get("id")]
    account = location.get("account") or location.get("project") or ""
    row: Dict[str, Any] = {
        "ObservedAt": _normalise_time(record.get("observed_at"), now=now, fixed=fixed),
        "RecordId": str(record.get("record_id") or ""),
        "EntityKey": str(record.get("entity_key") or ""),
        "GroupId": str(record.get("group_id") or ""),
        "SchemaVersion": str(record.get("schema") or SCHEMA_INVENTORY),
        "Kind": str(record.get("kind") or ""),
        "Surface": str(record.get("surface") or ""),
        "InventorySource": str(record.get("source") or ""),
        "Product": str(record.get("product") or ""),
        "Vendor": str(record.get("vendor") or ""),
        "Name": _truncate(str(record.get("name") or ""), _STRING_CAP),
        "Version": str(record.get("version") or ""),
        "HostId": str(location.get("host_id") or ""),
        "Hostname": str(location.get("hostname") or ""),
        "OsName": str(location.get("os") or ""),
        "UserHash": str(location.get("user") or ""),
        "Path": str(location.get("path") or ""),
        "Scope": str(location.get("scope") or ""),
        "RepoName": str(location.get("repo") or ""),
        "EntraTenantId": str(location.get("tenant_id") or ""),
        "PowerPlatformEnvironmentId": str(location.get("environment_id") or ""),
        "CloudAccount": str(account or ""),
        "Region": str(location.get("region") or ""),
        "Namespace": str(location.get("namespace") or ""),
    }
    if location:
        row["Location"] = _cap_dynamic(location, _DYNAMIC_CAP)
    if "managed" in governance:
        row["Managed"] = bool(governance.get("managed"))
    if governance.get("governed_by"):
        row["GovernedBy"] = str(governance.get("governed_by"))
    if "coverable" in governance:
        row["Coverable"] = bool(governance.get("coverable"))
    if governance.get("mode"):
        row["GovernanceMode"] = str(governance.get("mode"))
    if governance.get("approved") is not None:
        row["Approved"] = bool(governance.get("approved"))
    if "score" in risk and risk.get("score") is not None:
        try:
            row["RiskScore"] = int(risk.get("score"))
        except (TypeError, ValueError):
            pass
    if risk.get("level"):
        row["RiskLevel"] = str(risk.get("level"))
    if signal_ids:
        row["RiskSignalIds"] = signal_ids
    if signals:
        row["RiskSignals"] = _cap_dynamic(signals, _DYNAMIC_CAP)
    attributes = record.get("attributes")
    if isinstance(attributes, dict) and attributes:
        row["Attributes"] = _cap_dynamic(attributes, _ATTR_CAP)
    evidence = record.get("evidence")
    if evidence:
        row["Evidence"] = _cap_dynamic(evidence, _EVIDENCE_CAP)
    related = record.get("related")
    if related:
        row["Related"] = _cap_dynamic(related, _DYNAMIC_CAP)
    if run.get("run_id"):
        row["RunId"] = str(run.get("run_id"))
    if run.get("scanner_version"):
        row["ScannerVersion"] = str(run.get("scanner_version"))
    if run.get("collector_version") not in (None, ""):
        row["CollectorVersion"] = str(run.get("collector_version"))
    return _ordered(row, INVENTORY_COLUMNS)


def dumps_row(row: Dict[str, Any]) -> str:
    return json.dumps(row, ensure_ascii=False, separators=(",", ":"), sort_keys=False)
