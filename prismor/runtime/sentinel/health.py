"""Persistent Sentinel sink health. No tokens."""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Dict

from prismor.runtime.sentinel.auth import redact
from prismor.runtime.sentinel.config import SentinelSinkConfig


def health_path(cfg: SentinelSinkConfig) -> Path:
    override = os.environ.get("PRISMOR_HOME", "").strip()
    home = Path(override) if override else Path.home() / ".prismor"
    try:
        if not override:
            from prismor.runtime.store import prismor_home
            home = prismor_home()
    except Exception:
        pass
    return home / f"sentinel-{cfg.name}-health.json"


def empty_health(name: str) -> Dict[str, Any]:
    return {
        "sink": name,
        "state": "ok",
        "streams": {},
        "token": {"mode": "", "cached": False, "expires_in_s": 0},
        "backoff_until": None,
        "version": 1,
    }


def load(cfg: SentinelSinkConfig) -> Dict[str, Any]:
    path = health_path(cfg)
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        data = empty_health(cfg.name)
    if not isinstance(data, dict):
        data = empty_health(cfg.name)
    data.setdefault("streams", {})
    data.setdefault("token", {"mode": cfg.auth_mode, "cached": False, "expires_in_s": 0})
    return data


def save(cfg: SentinelSinkConfig, data: Dict[str, Any]) -> None:
    path = health_path(cfg)
    path.parent.mkdir(parents=True, exist_ok=True)
    # Belt: never persist a registered secret.
    text = redact(json.dumps(data, separators=(",", ":")))
    tmp = path.with_name(f"{path.name}.{os.getpid()}.tmp")
    tmp.write_text(text, encoding="utf-8")
    os.replace(tmp, path)


def stream_state(data: Dict[str, Any], key: str) -> Dict[str, Any]:
    streams = data.setdefault("streams", {})
    state = streams.setdefault(key, {
        "pending": 0, "pending_bytes": 0, "oldest_pending_s": 0,
        "last_success": None, "rows_sent": 0, "bytes_sent": 0, "batches_sent": 0,
        "retries": 0, "throttled": 0, "quarantined": 0,
        "dropped": {"overflow": 0, "age": 0, "oversize": 0, "filtered": 0},
        "last_error": None, "inline_budget_exhausted": 0,
    })
    state.setdefault("dropped", {"overflow": 0, "age": 0, "oversize": 0, "filtered": 0})
    return state
