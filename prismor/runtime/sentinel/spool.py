"""JSONL spool with peek/ack. Rows stay on disk until a 204 ack."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from prismor.runtime.sentinel.config import SentinelSinkConfig


def _home() -> Path:
    override = os.environ.get("PRISMOR_HOME", "").strip()
    if override:
        return Path(override)
    try:
        from prismor.runtime.store import prismor_home
        return prismor_home()
    except Exception:
        return Path.home() / ".prismor"


def spool_path(cfg: SentinelSinkConfig, stream_key: str) -> Path:
    return _home() / f"sentinel-{cfg.name}-{stream_key}.jsonl"


def quarantine_path(cfg: SentinelSinkConfig, stream_key: str) -> Path:
    return _home() / f"sentinel-{cfg.name}-{stream_key}.rejected.jsonl"


def flush_lock_path(cfg: SentinelSinkConfig, stream_key: str) -> Path:
    return _home() / f"sentinel-{cfg.name}-{stream_key}.flush.lock"


class Spool:
    def __init__(self, path: Path, *, max_records: int = 20_000, max_bytes: int = 52_428_800,
                 max_age_hours: float = 168) -> None:
        self.path = path
        self.max_records = max_records
        self.max_bytes = max_bytes
        self.max_age_hours = max_age_hours
        self.dropped = {"overflow": 0, "age": 0, "oversize": 0, "filtered": 0}

    def _lock(self):
        from prismor.runtime.store import file_lock
        return file_lock(self.path)

    def _read_lines(self) -> List[str]:
        if not self.path.exists():
            return []
        try:
            text = self.path.read_text(encoding="utf-8")
        except OSError:
            return []
        if not text:
            return []
        lines = text.splitlines()
        # A torn last line has no trailing newline and is not valid JSON.
        if text[-1] != "\n" and lines:
            last = lines[-1]
            try:
                json.loads(last)
            except ValueError:
                lines = lines[:-1]
        return [line for line in lines if line.strip()]

    def _write(self, lines: List[str]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_name(f"{self.path.name}.{os.getpid()}.tmp")
        payload = "".join(line + "\n" for line in lines)
        tmp.write_text(payload, encoding="utf-8")
        os.replace(tmp, self.path)

    def append(self, rows: Sequence[Dict[str, Any]], *, now: float) -> None:
        if not rows:
            return
        try:
            with self._lock():
                lines = self._read_lines()
                for row in rows:
                    lines.append(json.dumps({"q": now, "r": row}, ensure_ascii=False, separators=(",", ":")))
                self._enforce(lines)
        except OSError:
            return

    def _enforce(self, lines: List[str]) -> None:
        raw = "".join(line + "\n" for line in lines).encode("utf-8")
        while lines and (len(lines) > self.max_records or len(raw) > self.max_bytes):
            lines.pop(0)
            self.dropped["overflow"] += 1
            raw = "".join(line + "\n" for line in lines).encode("utf-8")
        self._write(lines)

    def peek(self, max_bytes: int, max_records: int) -> Tuple[List[Dict[str, Any]], Optional[Dict[str, Any]]]:
        with self._lock():
            lines = self._read_lines()
        chosen: List[str] = []
        rows: List[Dict[str, Any]] = []
        size = 0
        for line in lines:
            if len(chosen) >= max_records:
                break
            if chosen and size + len(line) > max_bytes:
                break
            try:
                item = json.loads(line)
            except ValueError:
                continue
            row = item.get("r") if isinstance(item, dict) else None
            if not isinstance(row, dict):
                continue
            chosen.append(line)
            rows.append(row)
            size += len(line)
        if not chosen:
            return [], None
        token = {"n": len(chosen), "sha": hashlib.sha256(chosen[0].encode("utf-8")).hexdigest()}
        return rows, token

    def ack(self, token: Optional[Dict[str, Any]]) -> bool:
        if not token:
            return False
        with self._lock():
            lines = self._read_lines()
            if not lines:
                return False
            digest = hashlib.sha256(lines[0].encode("utf-8")).hexdigest()
            if digest != token.get("sha"):
                return False
            count = int(token.get("n") or 0)
            self._write(lines[count:])
            return True

    def age_out(self, now: float) -> int:
        cutoff = now - (self.max_age_hours * 3600.0)
        removed = 0
        with self._lock():
            kept: List[str] = []
            for line in self._read_lines():
                try:
                    item = json.loads(line)
                    queued = float(item.get("q") or 0)
                except (ValueError, TypeError):
                    kept.append(line)
                    continue
                if queued < cutoff:
                    removed += 1
                else:
                    kept.append(line)
            if removed:
                self.dropped["age"] += removed
                self._write(kept)
        return removed

    def pending(self) -> Tuple[int, int, Optional[float]]:
        lines = self._read_lines()
        oldest = None
        for line in lines:
            try:
                item = json.loads(line)
                queued = float(item.get("q") or 0)
            except (ValueError, TypeError):
                continue
            oldest = queued if oldest is None else min(oldest, queued)
            break
        raw = "".join(line + "\n" for line in lines).encode("utf-8")
        return len(lines), len(raw), oldest

    def quarantine(self, row: Dict[str, Any], code: str, *, now: float) -> None:
        path = self.path.with_name(self.path.name.replace(".jsonl", ".rejected.jsonl"))
        path.parent.mkdir(parents=True, exist_ok=True)
        line = json.dumps({"q": now, "code": code, "r": row}, ensure_ascii=False, separators=(",", ":"))
        with self._lock():
            existing = []
            if path.exists():
                existing = [item for item in path.read_text(encoding="utf-8").splitlines() if item.strip()]
            existing.append(line)
            existing = existing[-1000:]
            tmp = path.with_name(f"{path.name}.{os.getpid()}.tmp")
            tmp.write_text("".join(item + "\n" for item in existing), encoding="utf-8")
            os.replace(tmp, path)
