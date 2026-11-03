"""Shared fixtures for the Sentinel sink tests. Not a pytest plugin."""
from __future__ import annotations

import json
from typing import Any, Dict

from tests.sentinel_fake import FakeAzure


DCR = "dcr-" + "ab" * 16


class FakeClock:
    def __init__(self, now: float = 0.0) -> None:
        self.now = now
        self.slept = []

    def __call__(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.slept.append(seconds)
        self.now += float(seconds)


def sink_dict(fake: FakeAzure, **overrides: Any) -> Dict[str, Any]:
    raw: Dict[str, Any] = {
        "type": "sentinel",
        "name": "hmlr-sentinel",
        "endpoint": fake.base,
        "dcr_immutable_id": DCR,
        "delivery": "inline",
        "gzip": False,
        "auth": {
            "mode": "client_secret",
            "tenant_id": "tenant-1",
            "client_id": "client-1",
            "client_secret": "s3cr3t-VALUE-123",
            "authority_host": fake.base,
        },
    }
    auth = overrides.pop("auth", None)
    raw.update(overrides)
    if auth:
        raw["auth"] = {**raw["auth"], **auth}
    return raw


def ingest_requests(fake: FakeAzure):
    return [item for item in fake.requests if "/dataCollectionRules/" in item["path"]]


def token_requests(fake: FakeAzure):
    return [item for item in fake.requests if item["path"].endswith("/oauth2/v2.0/token")]


def json_body(raw: bytes):
    return json.loads(raw.decode("utf-8"))
