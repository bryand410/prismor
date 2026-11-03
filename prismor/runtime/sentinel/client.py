"""Logs Ingestion API client. Success is HTTP 204."""
from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Dict, Optional

from prismor.runtime.sentinel.auth import redact
from prismor.runtime.sentinel.config import SentinelSinkConfig


@dataclass
class UploadResult:
    kind: str  # ok, retry, split, poison, auth, config
    status: int = 0
    retry_after: Optional[float] = None
    error_code: str = ""
    request_id: str = ""
    detail: str = ""


def _retry_after(headers: Dict[str, str], now: float) -> Optional[float]:
    raw = ""
    for key, value in headers.items():
        if key.lower() == "retry-after":
            raw = value.strip()
    if not raw:
        return None
    try:
        seconds = float(raw)
    except ValueError:
        from email.utils import parsedate_to_datetime
        try:
            when = parsedate_to_datetime(raw).timestamp()
        except (TypeError, ValueError, IndexError):
            return None
        seconds = when - now
    if seconds < 1:
        seconds = 1
    if seconds > 300:
        seconds = 300
    return seconds


class IngestionClient:
    def __init__(self, cfg: SentinelSinkConfig, *, transport=None) -> None:
        self.cfg = cfg
        self.transport = transport

    def upload(self, stream: str, body: bytes, *, gzipped: bool, token: str,
               timeout: float, now: float = 0.0) -> UploadResult:
        import urllib.error
        import urllib.request
        request_id = str(uuid.uuid4())
        url = (
            f"{self.cfg.endpoint}/dataCollectionRules/{self.cfg.dcr_immutable_id}"
            f"/streams/{stream}?api-version=2023-01-01"
        )
        from prismor.runtime.http_ua import user_agent
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "User-Agent": user_agent(),
            "x-ms-client-request-id": request_id,
        }
        if gzipped:
            headers["Content-Encoding"] = "gzip"
        if self.transport is not None:
            try:
                status, hdrs, raw = self.transport("POST", url, headers, body, timeout)
            except Exception as exc:
                return UploadResult("retry", detail=redact(exc.__class__.__name__))
            return self._classify(status, hdrs or {}, raw or b"", request_id, now)
        request = urllib.request.Request(url, data=body, headers=headers, method="POST")
        try:
            # Same default SSL context as sinks.py: SSL_CERT_FILE is honored, no custom CA bundle.
            with urllib.request.urlopen(request, timeout=timeout) as resp:  # nosec B310
                resp.read()
                hdrs = {k: v for k, v in resp.headers.items()}
                return self._classify(int(resp.status), hdrs, b"", request_id, now)
        except urllib.error.HTTPError as exc:
            raw = exc.read() if exc.fp else b""
            hdrs = {k: v for k, v in (exc.headers.items() if exc.headers else [])}
            return self._classify(int(exc.code), hdrs, raw, request_id, now)
        except Exception as exc:
            return UploadResult("retry", detail=redact(exc.__class__.__name__))

    def _classify(self, status: int, headers: Dict[str, str], body: bytes,
                  request_id: str, now: float) -> UploadResult:
        code = ""
        for key, value in headers.items():
            if key.lower() == "x-ms-error-code":
                code = value
            if key.lower() == "x-ms-request-id" and value:
                request_id = value
        if status in (204, 200, 202):
            # TODO(verify): 200/202 are not documented for this API. 204 is
            # the documented success. 200/202 are accepted defensively.
            return UploadResult("ok", status, request_id=request_id)
        if status == 400:
            return UploadResult("poison", status, error_code=code or "400", request_id=request_id,
                                detail=redact(body.decode("utf-8", errors="replace")))
        if status == 401:
            return UploadResult("auth", status, error_code=code or "401", request_id=request_id)
        if status == 403:
            return UploadResult("config", status, error_code=code or "403", request_id=request_id,
                                detail="Monitoring Metrics Publisher")
        if status == 404:
            return UploadResult("config", status, error_code=code or "404", request_id=request_id)
        if status == 413:
            return UploadResult("split", status, error_code=code or "413", request_id=request_id)
        if status == 429 or status in (500, 502, 503, 504):
            return UploadResult("retry", status, retry_after=_retry_after(headers, now),
                                error_code=code or str(status), request_id=request_id)
        if 400 <= status < 500:
            return UploadResult("config", status, error_code=code or str(status), request_id=request_id)
        return UploadResult("retry", status, error_code=code or str(status), request_id=request_id)
