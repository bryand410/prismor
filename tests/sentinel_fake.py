"""Local stand-in for Entra and the Logs Ingestion API. No network beyond 127.0.0.1."""
from __future__ import annotations

import gzip
import json
import threading
import time
from collections import defaultdict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Dict, List, Optional, Tuple
from urllib.parse import parse_qs, urlparse


class FakeAzure:
    def __init__(self, token: str = "fixture-token") -> None:
        self.token = token
        self.queues: Dict[str, List[Tuple[int, Dict[str, str], bytes]]] = defaultdict(list)
        self.requests: List[dict] = []
        self.strict_columns: Optional[set] = None
        self.poison = None  # callable(row) -> bool
        self.delay = 0.0
        self._lock = threading.Lock()
        handler = self._handler()
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        self.port = self.server.server_address[1]
        self.base = f"http://127.0.0.1:{self.port}"
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()

    def script(self, route: str, responses: List[Tuple[int, Dict[str, str], bytes]]) -> None:
        self.queues[route].extend(responses)

    def _handler(self):
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, fmt, *args):
                return

            def _route(self) -> str:
                path = urlparse(self.path).path
                if path.endswith("/oauth2/v2.0/token"):
                    return "token"
                if path.endswith("/metadata/identity/oauth2/token"):
                    return "imds"
                if path.endswith("/msi/token"):
                    return "msi"
                if "/dataCollectionRules/" in path:
                    return "ingest"
                return "other"

            def _read(self) -> bytes:
                length = int(self.headers.get("Content-Length") or 0)
                return self.rfile.read(length) if length else b""

            def _send(self, status: int, headers: Dict[str, str], body: bytes) -> None:
                with outer._lock:
                    if outer.requests:
                        outer.requests[-1]["status"] = status
                self.send_response(status)
                for key, value in headers.items():
                    self.send_header(key, value)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                if body:
                    self.wfile.write(body)

            def _record(self, raw: bytes) -> None:
                decoded = raw
                if (self.headers.get("Content-Encoding") or "").lower() == "gzip" and raw:
                    try:
                        decoded = gzip.decompress(raw)
                    except OSError:
                        decoded = raw
                form = {}
                ctype = self.headers.get("Content-Type") or ""
                if "application/x-www-form-urlencoded" in ctype and raw:
                    parsed = parse_qs(raw.decode("utf-8", errors="replace"))
                    form = {key: values[0] for key, values in parsed.items()}
                with outer._lock:
                    outer.requests.append({
                        "method": self.command,
                        "path": urlparse(self.path).path,
                        "query": urlparse(self.path).query,
                        "headers": {k: v for k, v in self.headers.items()},
                        "raw": raw,
                        "body": decoded,
                        "form": form,
                    })

            def _queued(self, route: str):
                with outer._lock:
                    queue = outer.queues.get(route) or []
                    if queue:
                        return queue.pop(0)
                return None

            def do_POST(self):
                raw = self._read()
                self._record(raw)
                route = self._route()
                if route == "ingest" and outer.delay:
                    time.sleep(outer.delay)
                queued = self._queued(route)
                if queued:
                    self._send(*queued)
                    return
                if route == "token":
                    body = json.dumps({"access_token": outer.token, "expires_in": 3600, "token_type": "Bearer"}).encode()
                    self._send(200, {"Content-Type": "application/json"}, body)
                    return
                if route == "ingest":
                    self._ingest(raw)
                    return
                self._send(404, {}, b"")

            def do_GET(self):
                self._record(b"")
                route = self._route()
                queued = self._queued(route)
                if queued:
                    self._send(*queued)
                    return
                if route in {"imds", "msi"}:
                    body = json.dumps({"access_token": outer.token, "expires_in": "3600", "expires_on": "4102444800"}).encode()
                    self._send(200, {"Content-Type": "application/json"}, body)
                    return
                self._send(404, {}, b"")

            def _ingest(self, raw: bytes) -> None:
                auth = self.headers.get("Authorization") or ""
                if auth != f"Bearer {outer.token}":
                    self._send(401, {"x-ms-error-code": "Unauthorized"}, b"")
                    return
                if len(raw) > 1_000_000:
                    self._send(413, {"x-ms-error-code": "RequestEntityTooLarge"}, b"")
                    return
                body = raw
                if (self.headers.get("Content-Encoding") or "").lower() == "gzip":
                    try:
                        body = gzip.decompress(raw)
                    except OSError:
                        self._send(400, {"x-ms-error-code": "InvalidGzip"}, b"bad gzip")
                        return
                if len(body) > 1_000_000:
                    self._send(413, {"x-ms-error-code": "RequestEntityTooLarge"}, b"")
                    return
                try:
                    payload = json.loads(body.decode("utf-8"))
                except ValueError:
                    self._send(400, {"x-ms-error-code": "InvalidJson"}, b"not json")
                    return
                if not isinstance(payload, list):
                    self._send(400, {"x-ms-error-code": "NotArray"}, b"not array")
                    return
                if outer.strict_columns is not None:
                    for row in payload:
                        if isinstance(row, dict) and not set(row).issubset(outer.strict_columns):
                            self._send(400, {"x-ms-error-code": "SchemaMismatch"}, b"schema")
                            return
                if outer.poison is not None and any(outer.poison(row) for row in payload if isinstance(row, dict)):
                    self._send(400, {"x-ms-error-code": "Poison"}, b"poison")
                    return
                self._send(204, {"x-ms-request-id": "fake-request"}, b"")

        return Handler
