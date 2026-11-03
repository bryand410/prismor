"""Pack Sentinel rows into JSON arrays under the Logs Ingestion size cap.

The service limit is 1 MB on both the compressed and the uncompressed body.
Batches are sized on the uncompressed JSON array.
"""
from __future__ import annotations

import gzip
import io
import json
from typing import Any, Dict, Iterator, List, NamedTuple, Sequence


class Batch(NamedTuple):
    body: bytes
    count: int
    rows: List[Dict[str, Any]]


def row_bytes(row: Dict[str, Any]) -> bytes:
    return json.dumps(row, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def array_size(parts: Sequence[bytes]) -> int:
    if not parts:
        return 2
    return 2 + sum(len(part) for part in parts) + (len(parts) - 1)


def gzip_body(body: bytes) -> bytes:
    buf = io.BytesIO()
    with gzip.GzipFile(fileobj=buf, mode="wb", compresslevel=6, mtime=0) as handle:
        handle.write(body)
    return buf.getvalue()


def _shrink(row: Dict[str, Any]) -> Dict[str, Any]:
    """Re-truncate dynamic and evidence fields to 4 KiB. Used for an oversize row."""
    shrunk = dict(row)
    for key in ("Evidence", "AdditionalFields", "Attributes", "RiskSignals", "Related", "Location"):
        if key not in shrunk:
            continue
        value = shrunk[key]
        if isinstance(value, str):
            raw = value.encode("utf-8")
            if len(raw) > 4096:
                shrunk[key] = raw[:4096].decode("utf-8", errors="ignore")
        else:
            encoded = json.dumps(value, ensure_ascii=False, separators=(",", ":"), default=str).encode("utf-8")
            if len(encoded) > 4096:
                shrunk[key] = {"_truncated": True, "_bytes": len(encoded)}
    return shrunk


def prepare_rows(rows: Sequence[Dict[str, Any]], max_bytes: int) -> tuple:
    """Return (sendable rows, quarantined oversize rows)."""
    sendable: List[Dict[str, Any]] = []
    quarantined: List[Dict[str, Any]] = []
    for row in rows:
        encoded = row_bytes(row)
        if len(encoded) + 2 <= max_bytes:
            sendable.append(row)
            continue
        shrunk = _shrink(row)
        if len(row_bytes(shrunk)) + 2 <= max_bytes:
            sendable.append(shrunk)
        else:
            quarantined.append(row)
    return sendable, quarantined


def iter_batches(rows: Sequence[Dict[str, Any]], max_bytes: int, max_records: int) -> Iterator[Batch]:
    """Greedy packs. A single row larger than the cap is not yielded (caller quarantines it)."""
    current: List[Dict[str, Any]] = []
    parts: List[bytes] = []
    for row in rows:
        encoded = row_bytes(row)
        if len(encoded) + 2 > max_bytes:
            continue
        trial = parts + [encoded]
        too_big = array_size(trial) > max_bytes
        too_many = len(current) >= max_records
        if current and (too_big or too_many):
            body = b"[" + b",".join(parts) + b"]"
            yield Batch(body, len(current), list(current))
            current = [row]
            parts = [encoded]
        else:
            current.append(row)
            parts.append(encoded)
    if current:
        body = b"[" + b",".join(parts) + b"]"
        yield Batch(body, len(current), list(current))
