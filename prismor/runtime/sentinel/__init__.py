"""Public Sentinel sink API. Imported lazily from ``sinks.dispatch``."""
from __future__ import annotations

import os
import sys
import threading
import time
from typing import Any, Dict, Iterable, List, Optional

_SEVERITY = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
_KICK = threading.Event()
_BG_SINKS: List[Dict[str, Any]] = []
_BG_STARTED = False


def _disabled() -> bool:
    return os.environ.get("PRISMOR_SENTINEL_DISABLE") == "1"


def _note_config_error(name: str, message: str) -> None:
    sys.stderr.write(f"[prismor] sentinel config: {message}\n")
    try:
        from prismor.runtime.sentinel.config import SentinelSinkConfig
        from prismor.runtime.sentinel import health as health_mod
        cfg = SentinelSinkConfig(name=name or "invalid", endpoint="https://invalid.example",
                                 dcr_immutable_id="dcr-" + "0" * 32, auth_mode="client_secret")
        doc = health_mod.empty_health(cfg.name)
        doc["state"] = "config_error"
        health_mod.save(cfg, doc)
    except Exception:
        return


def enqueue_events(sink: Dict[str, Any], events: Iterable[Dict[str, Any]], *, now: Optional[float] = None) -> None:
    if _disabled():
        return
    from prismor.runtime.sentinel.config import SentinelConfigError, parse
    from prismor.runtime.sentinel.delivery import resolve_delivery
    from prismor.runtime.sentinel.mapping import to_agent_event_row
    from prismor.runtime.sentinel.spool import Spool, spool_path
    try:
        cfg = parse(sink)
    except SentinelConfigError as exc:
        _note_config_error(str((sink or {}).get("name") or "invalid"), str(exc))
        return
    if not cfg.enabled or not cfg.events_stream:
        return
    stamp = time.time() if now is None else now
    floor = _SEVERITY.get(cfg.min_severity.upper(), -1) if cfg.min_severity else -1
    rows = []
    filtered = 0
    for event in events:
        rule = str(event.get("rule_id") or "")
        if rule == "audit-allowed" and not cfg.include_audit_allowed:
            filtered += 1
            continue
        rank = _SEVERITY.get(str(event.get("severity") or "").upper(), 0)
        if floor >= 0 and rank < floor:
            filtered += 1
            continue
        rows.append(to_agent_event_row(
            event, subject_mode=cfg.subject, subject_salt=cfg.subject_salt,
            include_evidence=cfg.include_evidence, now=stamp,
        ))
    spool = Spool(spool_path(cfg, "events"), max_records=cfg.spool_max_records,
                  max_bytes=cfg.spool_max_bytes, max_age_hours=cfg.spool_max_age_hours)
    try:
        spool.append(rows, now=stamp)
    except OSError:
        sys.stderr.write("[prismor] sentinel spool is not writable\n")
        return
    if filtered:
        from prismor.runtime.sentinel import health as health_mod
        doc = health_mod.load(cfg)
        state = health_mod.stream_state(doc, "events")
        state["dropped"]["filtered"] = int(state["dropped"].get("filtered") or 0) + filtered
        health_mod.save(cfg, doc)
    delivery = resolve_delivery(cfg)
    if delivery == "system":
        return
    trigger = "block" if any(str(event.get("action")) == "block" for event in events) else "enqueue"
    if delivery == "background":
        if trigger == "block" and cfg.flush_on_block:
            _KICK.set()
        return
    maybe_flush(sink, trigger=trigger, now=stamp)


def enqueue_inventory(sink: Dict[str, Any], records: Iterable[Dict[str, Any]], *, now: Optional[float] = None) -> None:
    if _disabled():
        return
    from prismor.runtime.sentinel.config import SentinelConfigError, parse
    from prismor.runtime.sentinel.mapping import to_inventory_row
    from prismor.runtime.sentinel.spool import Spool, spool_path
    try:
        cfg = parse(sink)
    except SentinelConfigError as exc:
        _note_config_error(str((sink or {}).get("name") or "invalid"), str(exc))
        return
    if not cfg.enabled or not cfg.inventory_stream:
        return
    stamp = time.time() if now is None else now
    rows = [to_inventory_row(record, now=stamp) for record in records]
    spool = Spool(spool_path(cfg, "inventory"), max_records=cfg.spool_max_records,
                  max_bytes=cfg.spool_max_bytes, max_age_hours=cfg.spool_max_age_hours)
    try:
        spool.append(rows, now=stamp)
    except OSError:
        sys.stderr.write("[prismor] sentinel spool is not writable\n")
        return


def maybe_flush(sink: Dict[str, Any], trigger: str = "enqueue", *, now: Optional[float] = None,
                budget_s: Optional[float] = None, transport=None, clock=None, sleep=None,
                rand=None, force: bool = False) -> Dict[str, Any]:
    from prismor.runtime.sentinel.config import SentinelConfigError, parse
    from prismor.runtime.sentinel.delivery import flush_config, resolve_delivery
    try:
        cfg = parse(sink)
    except SentinelConfigError as exc:
        _note_config_error(str((sink or {}).get("name") or "invalid"), str(exc))
        return {"state": "config_error"}
    delivery = resolve_delivery(cfg)
    if delivery == "system" and not force and trigger != "system":
        return {"skipped": "system"}
    inline_budget = budget_s
    if inline_budget is None and delivery == "inline":
        inline_budget = min(cfg.timeout_seconds * 2, cfg.inline_budget_seconds)
        if trigger == "exit":
            inline_budget = cfg.inline_budget_seconds
    if trigger == "discover":
        inline_budget = budget_s if budget_s is not None else 60
    return flush_config(cfg, budget_s=inline_budget, trigger=trigger, clock=clock, sleep=sleep,
                        rand=rand, transport=transport, force=force)


def flush(sink: Dict[str, Any], budget_s: float = 30, **kwargs) -> Dict[str, Any]:
    kwargs["force"] = True
    return maybe_flush(sink, trigger="flush", budget_s=budget_s, **kwargs)


def status(sink: Dict[str, Any]) -> Dict[str, Any]:
    from prismor.runtime.sentinel.config import SentinelConfigError, parse
    from prismor.runtime.sentinel import health as health_mod
    from prismor.runtime.sentinel.spool import Spool, spool_path
    try:
        cfg = parse(sink)
    except SentinelConfigError as exc:
        return {"sink": str((sink or {}).get("name") or ""), "state": "config_error", "error": str(exc)}
    doc = health_mod.load(cfg)
    for key, stream in (("events", cfg.events_stream), ("inventory", cfg.inventory_stream)):
        if not stream:
            continue
        spool = Spool(spool_path(cfg, key))
        pending, pending_bytes, oldest = spool.pending()
        state = health_mod.stream_state(doc, key)
        state["pending"] = pending
        state["pending_bytes"] = pending_bytes
        state["oldest_pending_s"] = 0 if oldest is None else max(0, time.time() - oldest)
    doc["token"]["mode"] = cfg.auth_mode
    return doc


def start_background(sinks: Optional[List[Dict[str, Any]]] = None) -> None:
    global _BG_STARTED
    from prismor.runtime.sentinel.delivery import set_background
    set_background(True)
    if sinks:
        _BG_SINKS.clear()
        _BG_SINKS.extend(sinks)
    if _BG_STARTED:
        return
    _BG_STARTED = True

    def _loop() -> None:
        last: Dict[str, float] = {}
        while True:
            kicked = _KICK.wait(timeout=0.2)
            _KICK.clear()
            for sink in list(_BG_SINKS):
                try:
                    from prismor.runtime.sentinel.config import parse as _parse
                    cfg = _parse(sink)
                    previous = last.get(cfg.name)
                    if previous is None:
                        last[cfg.name] = time.time()
                        previous = last[cfg.name]
                    if not kicked and time.time() - previous < cfg.flush_interval_seconds:
                        continue
                    maybe_flush(sink, trigger="block" if kicked else "background", force=True)
                    last[cfg.name] = time.time()
                except Exception:
                    continue
    threading.Thread(target=_loop, name="prismor-sentinel", daemon=True).start()


def configured_sinks(policy_outputs: Optional[List[Dict[str, Any]]] = None) -> List[Dict[str, Any]]:
    if policy_outputs is None:
        try:
            from prismor.runtime.policy_engine import PolicyEngine
            policy_outputs = list(PolicyEngine().outputs or [])
        except Exception:
            policy_outputs = []
    return [item for item in policy_outputs if str((item or {}).get("type") or "").lower() == "sentinel"]
