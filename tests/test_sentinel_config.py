"""S-CFG: sentinel sink configuration."""
from __future__ import annotations

import os
from pathlib import Path

import pytest

from prismor.runtime.sentinel.config import CLOUDS, SentinelConfigError, parse


def _base(**overrides):
    raw = {
        "type": "sentinel",
        "name": "hmlr-sentinel",
        "endpoint": "https://hmlr.uksouth-1.ingest.monitor.azure.com",
        "dcr_immutable_id": "dcr-" + "ab" * 16,
        "auth": {
            "mode": "client_secret",
            "tenant_id": "00000000-0000-0000-0000-000000000000",
            "client_id": "11111111-1111-1111-1111-111111111111",
            "client_secret": "${PRISMOR_SENTINEL_CLIENT_SECRET}",
        },
    }
    raw.update(overrides)
    return raw


def test_s_cfg_01_minimal_defaults():
    cfg = parse(_base())
    assert cfg.cloud == "public"
    assert cfg.gzip is True
    assert cfg.max_batch_bytes == 950000
    assert cfg.max_batch_records == 500
    assert cfg.events_stream == "Custom-PrismorAgentEvents"
    assert cfg.inventory_stream == "Custom-PrismorAIInventory"
    assert cfg.scope == CLOUDS["public"]["scope"]


def test_s_cfg_02_strips_path_and_slash():
    cfg = parse(_base(endpoint="https://hmlr.uksouth-1.ingest.monitor.azure.com/extra/"))
    assert cfg.endpoint == "https://hmlr.uksouth-1.ingest.monitor.azure.com"
    assert any("stripped" in warning for warning in cfg.warnings)


def test_s_cfg_03_rejects_http():
    with pytest.raises(SentinelConfigError):
        parse(_base(endpoint="http://evil.example/ingest"))


def test_s_cfg_04_batch_ceiling():
    with pytest.raises(SentinelConfigError):
        parse(_base(max_batch_bytes=2_000_000))


def test_s_cfg_05_exactly_one_secret():
    raw = _base()
    raw["auth"] = dict(raw["auth"], client_secret_file="C:/secret.txt")
    with pytest.raises(SentinelConfigError, match="exactly one"):
        parse(raw)


def test_s_cfg_06_stream_prefix():
    with pytest.raises(SentinelConfigError):
        parse(_base(streams={"events": "PrismorAgentEvents", "inventory": "Custom-PrismorAIInventory"}))


def test_s_cfg_07_legacy_collector_api():
    with pytest.raises(SentinelConfigError, match="deprecated") as exc:
        parse(_base(workspace_id="ws", shared_key="key"))
    assert "2026-09-14" in str(exc.value)


def test_s_cfg_08_usgov():
    cfg = parse(_base(cloud="usgov"))
    assert cfg.token_authority == "https://login.microsoftonline.us"
    assert cfg.scope == "https://monitor.azure.us/.default"


def test_s_cfg_09_china():
    cfg = parse(_base(cloud="china"))
    assert cfg.token_authority == "https://login.partner.microsoftonline.cn"
    assert cfg.scope == "https://monitor.azure.cn/.default"


def test_s_cfg_10_cloud_mismatch():
    cfg = parse(_base(endpoint="https://example.azure.us"))
    assert any("mismatch" in warning for warning in cfg.warnings)


def test_s_cfg_11_unknown_key():
    cfg = parse(_base(foo=1))
    assert any("foo" in warning for warning in cfg.warnings)


def test_s_cfg_12_dispatch_does_not_raise(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("PRISMOR_HOME", str(tmp_path))
    from prismor.runtime.sinks import dispatch
    dispatch(
        [{"severity": "LOW", "ruleId": "r", "title": "t", "evidence": "e", "id": "s:1"}],
        [{"type": "sentinel", "name": "bad name", "endpoint": "https://x", "dcr_immutable_id": "dcr-" + "ab" * 16,
          "auth": {"mode": "client_secret", "tenant_id": "t", "client_id": "c", "client_secret": "x"}},
         {"type": "file", "path": str(tmp_path / "out.log")}],
    )
    err = capsys.readouterr().err
    assert "sentinel config" in err
    assert (tmp_path / "out.log").is_file()
    health = list(tmp_path.glob("sentinel-*-health.json"))
    assert health
    assert "config_error" in health[0].read_text(encoding="utf-8")


def test_s_cfg_13_disable(tmp_path, monkeypatch):
    monkeypatch.setenv("PRISMOR_HOME", str(tmp_path))
    monkeypatch.setenv("PRISMOR_SENTINEL_DISABLE", "1")
    monkeypatch.setenv("PRISMOR_SENTINEL_ALLOW_INSECURE_LOCALHOST", "1")
    from prismor.runtime.sentinel import enqueue_events
    enqueue_events(_base(delivery="inline"), [{"rule_id": "r", "severity": "HIGH", "@timestamp": "2026-11-02T00:00:00Z"}])
    assert not list(tmp_path.glob("sentinel-*"))


def test_s_cfg_14_policy_validate(tmp_path, monkeypatch):
    monkeypatch.setenv("PRISMOR_SENTINEL_ALLOW_INSECURE_LOCALHOST", "1")
    policy = tmp_path / "policy.yaml"
    policy.write_text(
        "version: '1.0'\nrules: []\nsettings:\n  outputs:\n"
        "    - type: sentinel\n      name: hmlr-sentinel\n"
        "      endpoint: https://hmlr.uksouth-1.ingest.monitor.azure.com\n"
        "      dcr_immutable_id: dcr-" + "ab" * 16 + "\n"
        "      auth:\n        mode: client_secret\n"
        "        tenant_id: '00000000-0000-0000-0000-000000000000'\n"
        "        client_id: '11111111-1111-1111-1111-111111111111'\n"
        "        client_secret: ${PRISMOR_SENTINEL_CLIENT_SECRET}\n",
        encoding="utf-8",
    )
    from prismor.runtime.policy_engine import PolicyEngine
    engine = PolicyEngine(workspace=tmp_path)
    # The engine reads project policy from <workspace>/.prismor or the file we
    # pass through validate. Load the snippet directly.
    from prismor.runtime.sentinel.commands import validate_policy
    assert validate_policy(str(policy)) == 0
    assert engine is not None
    assert Path(policy).is_file()
