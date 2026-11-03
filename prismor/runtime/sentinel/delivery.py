"""Flush orchestration. One flusher per sink and stream.

The module is named ``delivery`` so importing it does not replace the
``flush`` function on the ``prismor.runtime.sentinel`` package.
"""
from __future__ import annotations

import os
import sys
import time
from typing import Any, Callable, Dict, List, Optional

from prismor.runtime.sentinel import health as health_mod
from prismor.runtime.sentinel.auth import AuthError, TokenProvider, redact
from prismor.runtime.sentinel.batcher import gzip_body, iter_batches, prepare_rows
from prismor.runtime.sentinel.client import IngestionClient
from prismor.runtime.sentinel.config import SentinelConfigError, SentinelSinkConfig, parse
from prismor.runtime.sentinel.spool import Spool, flush_lock_path, spool_path

_BACKGROUND = False


def background_enabled() -> bool:
    return _BACKGROUND


def set_background(enabled: bool) -> None:
    global _BACKGROUND
    _BACKGROUND = enabled


def resolve_delivery(cfg: SentinelSinkConfig) -> str:
    # ``parse`` already copies PRISMOR_SENTINEL_DELIVERY onto cfg.delivery.
    # A config built by hand still honours the env override here.
    env = os.environ.get("PRISMOR_SENTINEL_DELIVERY", "").strip()
    if env in {"system", "background", "inline"}:
        return env
    if cfg.delivery != "auto":
        return cfg.delivery
    if _BACKGROUND:
        return "background"
    if os.environ.get("PRISMOR_SYSTEM_SYNC") == "1":
        return "inline"
    try:
        from prismor.runtime.system_install import is_system_managed
        if is_system_managed():
            return "system"
    except Exception:
        pass
    return "inline"


def _jitter(rand: Callable, attempt: int) -> float:
    window = min(60.0, 1.0 * (2 ** attempt))
    if hasattr(rand, "uniform"):
        return float(rand.uniform(0, window))
    return float(rand()) * window


def _try_lock(path):
    """Non-blocking exclusive lock. Yields True when this process owns it."""
    from prismor.runtime.store import try_file_lock
    yield from try_file_lock(path)


def flush_config(cfg: SentinelSinkConfig, *, budget_s: Optional[float] = None, trigger: str = "flush",
                 clock=None, sleep=None, rand=None, transport=None, force: bool = False) -> Dict[str, Any]:
    """Drain one sink. ``force`` sends even when delivery is ``system``."""
    clock = clock or time.time
    sleep = sleep or time.sleep
    rand = rand or __import__("random").random
    if os.environ.get("PRISMOR_SENTINEL_DISABLE") == "1" or not cfg.enabled:
        return {"skipped": "disabled"}
    now = float(clock())
    doc = health_mod.load(cfg)
    backoff = doc.get("backoff_until")
    inline = resolve_delivery(cfg) == "inline" and not force
    if not force and backoff and now < float(backoff) and inline:
        return {"skipped": "backoff"}
    deadline = (time.monotonic() + budget_s) if budget_s is not None else None
    provider = TokenProvider(cfg, transport=transport, clock=clock)
    client = IngestionClient(cfg, transport=transport)
    summary = {"streams": {}}
    pairs = []
    if cfg.events_stream:
        pairs.append(("events", cfg.events_stream))
    if cfg.inventory_stream:
        pairs.append(("inventory", cfg.inventory_stream))
    for key, api_stream in pairs:
        path = spool_path(cfg, key)
        spool = Spool(path, max_records=cfg.spool_max_records, max_bytes=cfg.spool_max_bytes,
                      max_age_hours=cfg.spool_max_age_hours)
        spool.age_out(now)
        lock = flush_lock_path(cfg, key)
        locked = False
        for owned in _try_lock(lock):
            locked = owned
            if not owned:
                summary["streams"][key] = {"skipped": "locked"}
                break
            state = health_mod.stream_state(doc, key)
            rows, token = spool.peek(cfg.spool_max_bytes, cfg.spool_max_records)
            sendable, oversize = prepare_rows(rows, cfg.max_batch_bytes)
            for row in oversize:
                spool.quarantine(row, "oversize", now=now)
                state["dropped"]["oversize"] = int(state["dropped"].get("oversize") or 0) + 1
                state["quarantined"] = int(state.get("quarantined") or 0) + 1
            attempts = 1 if inline else cfg.max_attempts
            # Local send that honours attempts and Retry-After. Defined here so
            # it closes over the attempt budget.
            acked_rows: List[Dict[str, Any]] = []
            poisoned: List[Dict[str, Any]] = []

            def deliver(batch_rows: List[Dict[str, Any]], attempts_left: int, refreshed: bool = False):
                now_i = float(clock())
                if deadline is not None and time.monotonic() >= deadline:
                    state["inline_budget_exhausted"] = int(state.get("inline_budget_exhausted") or 0) + 1
                    return "budget", []
                call_timeout = cfg.timeout_seconds
                if deadline is not None:
                    call_timeout = max(0.05, min(cfg.timeout_seconds, deadline - time.monotonic()))
                try:
                    token_value = provider.get_token()
                except AuthError as exc:
                    doc["state"] = "auth_error"
                    doc["backoff_until"] = now_i + 900
                    state["last_error"] = {"at": now_i, "status": 0, "code": redact(exc.code), "request_id": ""}
                    sys.stderr.write(f"[prismor] sentinel auth failed: {redact(str(exc))}\n")
                    return "auth", []
                from prismor.runtime.sentinel.batcher import iter_batches as pack
                packed = list(pack(batch_rows, max(cfg.max_batch_bytes, 1_000_000), max(len(batch_rows), 1)))
                body = packed[0].body if packed else b"[]"
                use_gzip = cfg.gzip
                payload = gzip_body(body) if use_gzip else body
                if use_gzip and len(payload) > 1_000_000:
                    payload, use_gzip = body, False
                result = client.upload(api_stream, payload, gzipped=use_gzip, token=token_value,
                                       timeout=call_timeout, now=now_i)
                if deadline is not None and time.monotonic() >= deadline and result.kind != "ok":
                    state["inline_budget_exhausted"] = int(state.get("inline_budget_exhausted") or 0) + 1
                    floor = result.retry_after or 1
                    doc["backoff_until"] = now_i + floor
                    return "budget", []
                if os.environ.get("PRISMOR_SENTINEL_DEBUG") == "1":
                    sys.stderr.write(
                        f"[prismor] sentinel {result.status} bytes={len(body)} request={result.request_id}\n"
                    )
                if result.kind == "ok":
                    state["rows_sent"] = int(state.get("rows_sent") or 0) + len(batch_rows)
                    state["bytes_sent"] = int(state.get("bytes_sent") or 0) + len(body)
                    state["batches_sent"] = int(state.get("batches_sent") or 0) + 1
                    state["last_success"] = now_i
                    doc["state"] = "ok"
                    doc["backoff_until"] = None
                    return "ok", list(batch_rows)
                if result.kind == "auth" and not refreshed:
                    provider.invalidate()
                    return deliver(batch_rows, attempts_left, True)
                if result.kind == "auth":
                    doc["state"] = "auth_error"
                    doc["backoff_until"] = now_i + 900
                    state["last_error"] = {"at": now_i, "status": 401, "code": result.error_code,
                                           "request_id": result.request_id}
                    return "auth", []
                if result.kind == "split" and len(batch_rows) > 1:
                    mid = len(batch_rows) // 2
                    cfg.max_batch_bytes = max(1024, cfg.max_batch_bytes // 2)
                    _, left = deliver(batch_rows[:mid], attempts_left, refreshed)
                    _, right = deliver(batch_rows[mid:], attempts_left, refreshed)
                    return "ok", left + right
                if result.kind == "poison":
                    if len(batch_rows) > 1:
                        mid = len(batch_rows) // 2
                        left_status, left = deliver(batch_rows[:mid], attempts_left, refreshed)
                        right_status, right = deliver(batch_rows[mid:], attempts_left, refreshed)
                        if not left and not right and left_status in {"poison", "schema"} and right_status in {"poison", "schema"}:
                            # First all-fail bisect level: every row in this
                            # batch was rejected. Keep the rows, do not
                            # quarantine the flood, and stop this branch.
                            ids = {id(row) for row in batch_rows}
                            poisoned[:] = [row for row in poisoned if id(row) not in ids]
                            doc["state"] = "schema_error"
                            doc["backoff_until"] = now_i + 900
                            return "schema", []
                        return "partial", left + right
                    poisoned.append(batch_rows[0])
                    state["last_error"] = {"at": now_i, "status": 400, "code": result.error_code,
                                           "request_id": result.request_id}
                    return "poison", []
                if result.kind == "config":
                    doc["state"] = {403: "forbidden", 404: "not_found"}.get(result.status, "config_error")
                    doc["backoff_until"] = now_i + 900
                    state["last_error"] = {"at": now_i, "status": result.status, "code": result.error_code,
                                           "request_id": result.request_id}
                    return "config", []
                state["retries"] = int(state.get("retries") or 0) + 1
                if result.status == 429:
                    state["throttled"] = int(state.get("throttled") or 0) + 1
                state["last_error"] = {"at": now_i, "status": result.status, "code": result.error_code,
                                       "request_id": result.request_id}
                if inline or attempts_left <= 1:
                    floor = result.retry_after or 0
                    doc["backoff_until"] = now_i + (floor or 1)
                    if deadline is not None:
                        state["inline_budget_exhausted"] = int(state.get("inline_budget_exhausted") or 0) + 1
                    return "retry", []
                floor = result.retry_after or 0
                extra = _jitter(rand, max(0, attempts - attempts_left))
                sleep(floor + extra if floor else extra)
                return deliver(batch_rows, attempts_left - 1, refreshed)

            stop = ""
            planned = list(iter_batches(sendable, cfg.max_batch_bytes, cfg.max_batch_records))
            for batch in planned:
                status, got = deliver(batch.rows, attempts, False)
                acked_rows.extend(got)
                if status in {"budget", "auth", "config", "retry", "schema"}:
                    stop = status
                    break
            if stop == "retry" and doc.get("state") == "ok":
                doc["state"] = "unavailable"
            if poisoned and len(poisoned) == len(sendable) and not acked_rows:
                poisoned.clear()
                doc["state"] = "schema_error"
                doc["backoff_until"] = float(clock()) + 900
            else:
                for row in poisoned:
                    spool.quarantine(row, str((state.get("last_error") or {}).get("code") or "400"), now=now)
                    state["quarantined"] = int(state.get("quarantined") or 0) + 1
                done = {id(row) for row in acked_rows} | {id(row) for row in poisoned}
                consumed = 0
                for row in sendable:
                    if id(row) not in done:
                        break
                    consumed += 1
                if consumed and token:
                    spool.ack({"n": consumed, "sha": token.get("sha")})
            pending, pending_bytes, oldest = spool.pending()
            state["pending"] = pending
            state["pending_bytes"] = pending_bytes
            state["oldest_pending_s"] = 0 if oldest is None else max(0, float(clock()) - oldest)
            state["dropped"]["overflow"] = int(state["dropped"].get("overflow") or 0) + spool.dropped["overflow"]
            state["dropped"]["age"] = int(state["dropped"].get("age") or 0) + spool.dropped["age"]
            summary["streams"][key] = {"acked": len(acked_rows), "stop": stop, "pending": pending}
            break
        if not locked:
            continue
    doc["token"] = {"mode": cfg.auth_mode, "cached": True, "expires_in_s": 0}
    doc["sink"] = cfg.name
    health_mod.save(cfg, doc)
    summary["state"] = doc.get("state")
    return summary


def safe_parse(raw: Dict[str, Any]):
    try:
        return parse(raw), None
    except SentinelConfigError as exc:
        return None, exc
