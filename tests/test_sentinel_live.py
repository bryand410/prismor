"""S-LIVE: opt-in upload against a real workspace. Skipped until HMLR answers Q1–Q3."""
from __future__ import annotations

import os
import uuid

import pytest

pytestmark = pytest.mark.skipif(
    os.environ.get("PRISMOR_SENTINEL_LIVE") != "1",
    reason="live Sentinel test waits on an HMLR subscription, workspace, and sender identity",
)


def _ready():
    needed = (
        "PRISMOR_SENTINEL_LIVE_ENDPOINT", "PRISMOR_SENTINEL_LIVE_DCR",
        "PRISMOR_SENTINEL_LIVE_TENANT", "PRISMOR_SENTINEL_LIVE_CLIENT_ID",
    )
    return all(os.environ.get(name) for name in needed) and (
        os.environ.get("PRISMOR_SENTINEL_LIVE_SECRET") or os.environ.get("PRISMOR_SENTINEL_LIVE_CERT_FILE")
    )


@pytest.mark.skipif(not _ready(), reason="PRISMOR_SENTINEL_LIVE_* is incomplete")
def test_s_live_01_posts_three_rows():
    from prismor.runtime.sentinel.commands import run_test
    sink = {
        "type": "sentinel",
        "name": "hmlr-sentinel",
        "endpoint": os.environ["PRISMOR_SENTINEL_LIVE_ENDPOINT"],
        "dcr_immutable_id": os.environ["PRISMOR_SENTINEL_LIVE_DCR"],
        "auth": {
            "mode": "client_certificate" if os.environ.get("PRISMOR_SENTINEL_LIVE_CERT_FILE") else "client_secret",
            "tenant_id": os.environ["PRISMOR_SENTINEL_LIVE_TENANT"],
            "client_id": os.environ["PRISMOR_SENTINEL_LIVE_CLIENT_ID"],
            "client_secret": os.environ.get("PRISMOR_SENTINEL_LIVE_SECRET", ""),
            "certificate_file": os.environ.get("PRISMOR_SENTINEL_LIVE_CERT_FILE", ""),
        },
        "delivery": "inline",
    }
    assert run_test(sink) == 0
    assert uuid.uuid4()


@pytest.mark.slow
@pytest.mark.skipif(
    not os.environ.get("PRISMOR_SENTINEL_LIVE_WORKSPACE_ID"),
    reason="TODO(verify): Log Analytics query API https://api.loganalytics.azure.com/v1/workspaces/{id}/query",
)
def test_s_live_02_rows_queryable():
    pytest.skip("query polling waits on a workspace credential")
