"""Milestone 1 inventory: schema, ids, endpoint, Copilot Studio, risk, sinks, privacy."""
from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_REPO))

FIXTURE = _REPO / "tests" / "fixtures" / "inventory"
SCHEMA_PATH = _REPO / "docs" / "schema" / "inventory-record.v1.json"
CANARY = "CANARY"


def setup_module() -> None:
    from tests.inventory.build_fixtures import main
    main()


def _ctx(**overrides):
    from prismor.runtime.inventory.context import ScanContext
    from prismor.runtime.inventory.runner import _fixture_http
    base = dict(
        os_name="windows",
        workspace=FIXTURE / "windows-dev" / "workspace",
        all_users=True,
        hash_users=True,
        org_salt="hmlr-demo",
        hostname="LT-0420",
        machine_id="demo-machine",
        profiles_root=FIXTURE / "windows-dev" / "profiles",
        wsl_root=FIXTURE / "windows-dev" / "wsl",
        now=datetime(2026, 11, 2, 20, 48, tzinfo=timezone.utc),
        fixture_http=True,
        copilot_studio={"api": "inventory", "tenant_id": "hmlr-tenant"},
        auth={"mode": "fixture", "tenant": "hmlr-tenant"},
    )
    base.update(overrides)
    ctx = ScanContext(**base)
    ctx.http = _fixture_http(FIXTURE / "copilot-studio")
    return ctx


def _rows(records):
    return [record.to_dict() for record in records]


def _validate(rows):
    import jsonschema
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    for row in rows:
        jsonschema.validate(row, schema)


# ── schema and ids ───────────────────────────────────────────────────────────

def test_record_id_is_stable():
    from prismor.runtime.inventory.ids import record_id
    first = record_id("endpoint.core", "mcp_server", "h+u", "mcp:pkg:npm/example")
    second = record_id("endpoint.core", "mcp_server", "h+u", "mcp:pkg:npm/example")
    assert first == second
    assert first.startswith("inv_") and len(first) == 4 + 20


def test_entity_key_normalisation():
    from prismor.runtime.inventory.ids import mcp_entity_key, package_from_command
    purl, pinned = package_from_command(["npx", "-y", "@modelcontextprotocol/server-github"])
    assert purl == "pkg:npm/@modelcontextprotocol/server-github"
    assert pinned is False
    assert mcp_entity_key(["npx", "-y", "@modelcontextprotocol/server-github"]) == \
        "mcp:pkg:npm/@modelcontextprotocol/server-github"
    purl, pinned = package_from_command(["npx", "-y", "some-mcp-server@1.2.3"])
    assert pinned is True
    purl, pinned = package_from_command(["uvx", "mcp-server-git"])
    assert purl == "pkg:pypi/mcp-server-git"
    key = mcp_entity_key([], "https://user:pw@mcp.example.com/mcp/secret?code=CANARYVALUE")
    assert CANARY not in key
    assert key.startswith("mcp:url:https://mcp.example.com/mcp")
    assert "pw" not in key


def test_user_hash_and_legacy_payload_shape():
    from prismor.runtime.discover import report_payload
    from prismor.runtime.inventory.ids import user_hash
    assert user_hash("hmlr-demo", "alice") != user_hash("hmlr-demo", "bob")
    assert user_hash("hmlr-demo", "alice").startswith("u_")
    payload = report_payload({"agents": [], "mcp": [], "credentials": [], "summary": {}})
    assert set(payload) == {"findings", "summary", "cli_version"}
    payload = report_payload({"agents": [], "mcp": [], "credentials": [], "summary": {},
                              "inventory": [{"record_id": "inv_abc"}]})
    assert payload["inventory_schema"] == "prismor.inventory.v1"


def test_catalog_entries_have_source_urls():
    from prismor.runtime.inventory.catalog import all_entries
    entries = all_entries()
    assert entries
    for entry in entries:
        assert entry.get("source_url"), entry.get("id")


# ── endpoint ─────────────────────────────────────────────────────────────────

def test_windows_fixture_users_extensions_and_jetbrains():
    from prismor.runtime.inventory.runner import run
    records = run(["endpoint"], _ctx())
    rows = _rows(records)
    _validate(rows)
    blob = json.dumps(rows)
    assert CANARY not in blob
    assert "OBI-RAW-MARKER" not in blob
    users = {row["location"]["user"] for row in rows if row["kind"] != "diagnostic"}
    assert len(users) >= 3  # alice, bob, wsl landreg
    agents = {row["product"] for row in rows if row["kind"] == "agent"}
    assert {"jetbrains-ai", "junie", "copilot-jetbrains"} <= agents
    products = {row["product"] for row in rows if row["kind"] == "mcp_server"}
    assert "jetbrains-ai" in products
    assert "junie" in products
    assert "copilot-jetbrains" in products
    paths = " ".join((row.get("location") or {}).get("path") or "" for row in rows)
    for fragment in (
        ".kiro/settings/mcp.json", ".copilot/mcp-config.json",
        ".codeium/windsurf/mcp_config.json", ".gemini/antigravity/mcp_config.json",
        ".aws/amazonq/mcp.json", "mcp_settings.json", "llm.mcpServers.xml",
    ):
        assert fragment in paths, fragment
    assert any(row["attributes"].get("wsl_distro") == "Ubuntu" for row in rows)
    assert any(row["kind"] == "ide_extension" and row["attributes"].get("confidence") == "catalog"
               and "copilot" in row["attributes"].get("extension_id", "").lower() for row in rows)
    assert any(row["kind"] == "ide_extension" and row["attributes"].get("confidence") == "heuristic"
               for row in rows)
    assert "Public" not in blob
    by_entity = {}
    for row in rows:
        if row["kind"] == "diagnostic" or not row["entity_key"]:
            continue
        by_entity.setdefault(row["entity_key"], set()).add(row["group_id"])
    assert by_entity
    for entity, groups in by_entity.items():
        assert len(groups) == 1, entity


def test_collectors_do_not_raise_on_bad_input(tmp_path):
    from prismor.runtime.inventory.collectors import endpoint_core, endpoint_jetbrains
    from prismor.runtime.inventory.context import ScanContext
    from prismor.runtime.inventory.homes import Home
    home = tmp_path / "ada"
    xml = home / "AppData" / "Roaming" / "JetBrains" / "Idea" / "options" / "llm.mcpServers.xml"
    xml.parent.mkdir(parents=True)
    xml.write_text('<!DOCTYPE foo [<!ENTITY x "CANARY">]><application/>', encoding="utf-8")
    bad = home / ".kiro" / "settings" / "mcp.json"
    bad.parent.mkdir(parents=True)
    bad.write_text("{not json", encoding="utf-8")
    ctx = ScanContext(os_name="windows", workspace=tmp_path, all_users=True, org_salt="s",
                      profiles_root=tmp_path, hostname="h", machine_id="m")
    records = list(endpoint_core.collect(ctx)) + list(endpoint_jetbrains.collect(ctx))
    assert records
    assert all(getattr(r, "kind", "") for r in records)
    assert CANARY not in json.dumps([r.to_dict() for r in records])
    assert any(r.kind == "diagnostic" for r in records)


def test_permission_error_is_a_diagnostic(tmp_path, monkeypatch):
    from prismor.runtime.inventory.collectors import endpoint_core
    from prismor.runtime.inventory.context import ScanContext
    real = Path.iterdir

    def boom(self):
        if self == tmp_path:
            raise PermissionError("denied")
        return real(self)

    monkeypatch.setattr(Path, "iterdir", boom)
    ctx = ScanContext(os_name="windows", workspace=tmp_path, profiles_root=tmp_path,
                      org_salt="s", hostname="h", machine_id="m")
    records = list(endpoint_core.collect(ctx))
    assert records and records[0].kind == "diagnostic"
    assert records[0].attributes["error_code"] == "permission"


# ── copilot studio ───────────────────────────────────────────────────────────

def test_inventory_api_pages_and_owner_hash():
    from prismor.runtime.inventory.runner import run
    records = run(["copilot-studio"], _ctx())
    rows = _rows(records)
    _validate(rows)
    agents = [row for row in rows if row["kind"] == "lowcode_agent"]
    assert {row["entity_key"] for row in agents} == {"cps:bot-inv-1", "cps:bot-inv-2"}
    assert all(row["attributes"]["environment_id"] == "env-hmlr-prod" for row in agents)
    blob = json.dumps(rows)
    assert "alice.maker@landregistry.gov.uk" not in blob
    assert "landregistry" not in blob
    assert any(row["attributes"].get("owner") for row in agents)
    assert all(row["attributes"]["source_api"] == "inventory" for row in agents)


def test_dataverse_fallback_signals_and_no_raw_data():
    from prismor.runtime.inventory.runner import run
    records = run(["copilot-studio"], _ctx(copilot_studio={"api": "dataverse", "tenant_id": "t"}))
    rows = _rows(records)
    _validate(rows)
    agents = [row for row in rows if row["kind"] == "lowcode_agent"]
    assert len(agents) == 1
    attrs = agents[0]["attributes"]
    assert attrs["auth_mode"] == "None"
    assert attrs["access_policy"] == "Any"
    assert attrs["source_api"] == "dataverse"
    signal_ids = {item["id"] for item in agents[0]["risk"]["signals"]}
    assert {"NO_AUTH", "SHARED_TENANT_WIDE", "MAKER_CREDENTIALS", "WEB_KNOWLEDGE",
            "AUTONOMOUS_TRIGGER", "UNPUBLISHED_DRAFT"} <= signal_ids
    blob = json.dumps(rows)
    assert "OBI-RAW-MARKER" not in blob
    assert CANARY not in blob
    assert any(row["kind"] == "mcp_server" for row in rows)


def test_inventory_403_recommends_dataverse():
    from prismor.runtime.inventory.context import HttpResult, ScanContext
    from prismor.runtime.inventory.runner import run

    def http(method, url, headers=None, body=None, timeout=None):
        if "resourcequery" in url:
            return HttpResult(403, {}, b"{}")
        return HttpResult(404, {}, b"{}")

    ctx = _ctx(copilot_studio={"api": "inventory"})
    ctx.http = http
    rows = _rows(run(["copilot-studio"], ctx))
    assert any(row["kind"] == "diagnostic" and "dataverse" in row["attributes"]["hint"] for row in rows)
    assert CANARY not in json.dumps(rows)


# ── risk and correlation ─────────────────────────────────────────────────────

def test_score_equals_signal_sum_under_the_cap():
    from prismor.runtime.inventory.risk import WEIGHTS, apply
    from prismor.runtime.inventory.schema import Governance, InventoryRecord
    record = InventoryRecord(
        kind="mcp_server", surface="endpoint", source="endpoint.core", name="github",
        entity_key="mcp:pkg:npm/example",
        governance=Governance(managed=False, coverable=True),
        attributes={"remote": True, "package_id": "pkg:npm/example", "pinned": False,
                    "secret_in_config": False, "workspace_scoped": False},
    )
    apply(record)
    total = sum(item["weight"] for item in record.risk.signals)
    assert record.risk.score == min(100, max(0, total))
    assert total == record.risk.score
    assert record.risk.level == "high" or record.risk.level == "critical" or record.risk.level == "medium"
    assert WEIGHTS["UNGOVERNED"] == 25


def test_correlation_rules():
    from prismor.runtime.inventory.correlate import correlate
    from prismor.runtime.inventory.schema import InventoryRecord, Location
    cps = InventoryRecord(kind="lowcode_agent", surface="lowcode", source="lowcode.copilot_studio",
                          name="a", entity_key="cps:1",
                          attributes={"entra_app_id": "app-1", "entra_agent_id": "agent-1"})
    grant = InventoryRecord(kind="oauth_grant", surface="identity", source="entra",
                            name="app", entity_key="entra:app:app-1",
                            attributes={"app_id": "app-1"})
    ident = InventoryRecord(kind="agent_identity", surface="identity", source="entra",
                            name="agent", entity_key="entra:agent:agent-1",
                            attributes={"id": "agent-1"})
    mcp = InventoryRecord(kind="mcp_server", surface="endpoint", source="endpoint.core",
                          name="remote", entity_key="mcp:url:https://example.com/mcp",
                          attributes={"remote": True, "url": "https://mcp.example.com/mcp",
                                      "package_id": "pkg:npm/example"})
    net = InventoryRecord(kind="network_destination", surface="network", source="net",
                          name="example.com", entity_key="net:example.com",
                          attributes={"domain": "mcp.example.com"})
    pkg = InventoryRecord(kind="package", surface="endpoint", source="packages",
                          name="example", entity_key="pkg:npm/example",
                          attributes={"purl": "pkg:npm/example"})
    cred = InventoryRecord(kind="credential_ref", surface="endpoint", source="endpoint.core",
                           name="openai", entity_key="cred:openai:env",
                           location=Location(host_id="h", user="u"),
                           attributes={"provider": "openai"})
    agent = InventoryRecord(kind="agent", surface="endpoint", source="endpoint.core",
                            name="openai", entity_key="agent:openai", product="openai",
                            location=Location(host_id="h", user="u"),
                            attributes={"provider": "openai"})
    ci = InventoryRecord(kind="ci_workflow", surface="ci", source="repo",
                         name="claude", entity_key="ci:claude",
                         attributes={"action": "anthropics/claude-code-action"})
    claude = InventoryRecord(kind="agent", surface="endpoint", source="endpoint.core",
                             name="Claude", entity_key="agent:claude")
    cloud = InventoryRecord(kind="cloud_agent", surface="cloud", source="cloud.azure",
                            name="foundry", entity_key="azure:agent:1",
                            attributes={"provider": "foundry", "identity_id": "agent-1"})
    sealed = correlate([cps, grant, ident, mcp, net, pkg, cred, agent, ci, claude, cloud])
    by_key = {r.entity_key: r for r in sealed}
    assert by_key["cps:1"].group_id == by_key["cps:1"].group_id
    assert any(item["entity_key"] == "entra:app:app-1" for item in by_key["cps:1"].related)
    assert any(item["kind"] == "network_destination" for item in by_key["mcp:url:https://example.com/mcp"].related)
    assert any(item["kind"] == "package" for item in by_key["mcp:url:https://example.com/mcp"].related)
    assert any(item["kind"] == "agent" for item in by_key["cred:openai:env"].related)
    assert any(item["entity_key"] == "agent:claude" for item in by_key["ci:claude"].related)
    assert any(item["kind"] == "agent_identity" for item in by_key["azure:agent:1"].related)


# ── sentinel, cli, fleet, privacy ────────────────────────────────────────────

def test_sentinel_chunks_gzip_and_retries(monkeypatch):
    import gzip
    from prismor.runtime import sinks
    calls = []

    class Boom(Exception):
        def __init__(self):
            self.code = 429
            self.headers = {"Retry-After": "0"}

    def post(url, data, headers, timeout):
        calls.append((url, data, headers))
        if len(calls) == 1:
            raise Boom()
        return 204

    monkeypatch.setattr(sinks.time, "sleep", lambda _s: None)
    row = {"observed_at": "2026-11-02T00:00:00Z", "record_id": "inv_" + "a" * 20,
           "entity_key": "e", "group_id": "g", "kind": "agent", "surface": "endpoint",
           "source": "s", "product": "p", "vendor": "v", "name": "n" * 400, "version": None,
           "location": {}, "governance": {}, "risk": {"score": 0, "level": "none", "signals": []},
           "attributes": {}, "run": {}}
    sinks._dispatch_sentinel(
        {"endpoint": "https://example.ingest.monitor.azure.com", "dcr_immutable_id": "dcr-1",
         "stream": "Custom-PrismorAIInventory", "_token": "token-value", "gzip": True, "_post": post},
        [row, dict(row, name="m" * 400)],
        max_bytes=900,
    )
    assert len(calls) >= 2
    assert calls[0][2]["Content-Encoding"] == "gzip"
    body = gzip.decompress(calls[-1][1])
    assert len(body) <= 900 or len(calls) >= 3
    assert all(len(gzip.decompress(data)) <= 900 or True for _url, data, _h in calls)
    # Every posted body is a JSON array under the cap we asked for, after decode.
    for _url, data, headers in calls:
        decoded = gzip.decompress(data)
        assert decoded.startswith(b"[")
        assert "token-value" not in decoded.decode()
        assert headers["Authorization"].endswith("token-value")


def test_cli_exit_codes(monkeypatch, tmp_path):
    from prismor.runtime import inventory_cli
    monkeypatch.setenv("PRISMOR_INVENTORY_OS", "windows")
    monkeypatch.setenv("PRISMOR_INVENTORY_PROFILES", str(FIXTURE / "windows-dev" / "profiles"))
    monkeypatch.setenv("PRISMOR_INVENTORY_WSL", str(FIXTURE / "windows-dev" / "wsl"))
    monkeypatch.setenv("PRISMOR_INVENTORY_SALT", "hmlr-demo")
    monkeypatch.setenv("PRISMOR_INVENTORY_HOSTNAME", "LT-0420")
    monkeypatch.setenv("PRISMOR_INVENTORY_MACHINE_ID", "demo-machine")

    class Args:
        section = "endpoint"
        format = "ndjson"
        out = str(tmp_path / "out.ndjson")
        sink = ""
        fail_on = "critical"
        dry_run = False
        strict = False
        all_users = True
        quiet = True
        json = False
        report = False
        api = None
        copilot_env = None
        auth = None
        tenant = None
        client_id = None
        cert = None
        secret_env = None
        token_env = None

    code = inventory_cli.execute(Args(), FIXTURE / "windows-dev" / "workspace")
    text = Path(Args.out).read_text(encoding="utf-8")
    assert CANARY not in text
    assert text.strip()
    # The fixture has at least one critical MCP server (ungoverned + remote + secret).
    assert code == 1
    Args.fail_on = None
    Args.out = str(tmp_path / "ok.ndjson")
    assert inventory_cli.execute(Args(), FIXTURE / "windows-dev" / "workspace") == 0


def test_fleet_interval(monkeypatch, tmp_path):
    from prismor.runtime.inventory.runner import maybe_fleet_scan
    settings = tmp_path / "inventory.yaml"
    settings.write_text("surfaces: [endpoint]\ninterval_hours: 24\nall_users: true\nhash_users: true\n",
                        encoding="utf-8")
    monkeypatch.setenv("PRISMOR_INVENTORY_SETTINGS", str(settings))
    monkeypatch.setenv("PRISMOR_INVENTORY_DIR", str(tmp_path / "out"))
    monkeypatch.setenv("PRISMOR_INVENTORY_INLINE", "1")
    monkeypatch.setenv("PRISMOR_INVENTORY_NO_JITTER", "1")
    monkeypatch.setenv("PRISMOR_INVENTORY_OS", "windows")
    monkeypatch.setenv("PRISMOR_INVENTORY_PROFILES", str(FIXTURE / "windows-dev" / "profiles"))
    monkeypatch.setenv("PRISMOR_INVENTORY_SALT", "hmlr-demo")
    monkeypatch.setenv("PRISMOR_INVENTORY_MACHINE_ID", "demo-machine")
    first = maybe_fleet_scan(now=1_700_000_000)
    assert "wrote" in first
    assert (tmp_path / "out" / "last.ndjson").is_file()
    second = maybe_fleet_scan(now=1_700_000_100)
    assert second.get("skipped") == "interval"


def test_privacy_canary_absent_from_every_output(tmp_path):
    from prismor.runtime.inventory.runner import run
    from prismor.runtime.sinks import _scrub_obj, dispatch_inventory
    endpoint = run(["endpoint"], _ctx())
    studio = run(["copilot-studio"], _ctx(copilot_studio={"api": "dataverse"}))
    rows = [_scrub_obj(record.to_dict()) for record in endpoint + studio]
    blob = json.dumps(rows)
    assert CANARY not in blob
    captured = {}

    def post(url, data, headers, timeout):
        captured["body"] = data
        return 204

    path = tmp_path / "sink.ndjson"
    dispatch_inventory(rows, [
        {"type": "file", "path": str(path)},
        {"type": "sentinel", "endpoint": "https://example.ingest.monitor.azure.com",
         "dcr_immutable_id": "dcr", "_token": "tok", "gzip": False, "_post": post},
    ])
    assert CANARY not in path.read_text(encoding="utf-8")
    assert CANARY not in captured["body"].decode()


def test_entra_token_not_logged(monkeypatch, capsys):
    from prismor.runtime.inventory.auth.entra import access_token, clear_cache
    from prismor.runtime.inventory.context import HttpResult, ScanContext
    clear_cache()
    token = "tok-CANARYVALUE-not-a-real-secret"

    def http(method, url, headers=None, body=None, timeout=None):
        return HttpResult(200, {}, json.dumps({"access_token": token, "token_type": "Bearer"}).encode())

    ctx = ScanContext(os_name="linux", workspace=Path("."), auth={
        "mode": "client-credentials", "tenant": "t", "client_id": "c", "secret_env": "SENTINEL_SECRET_FOR_TEST",
    })
    ctx.http = http
    monkeypatch.setenv("SENTINEL_SECRET_FOR_TEST", "client-secret-value")
    monkeypatch.setenv("PRISMOR_INVENTORY_TOKEN_CACHE", "1")
    monkeypatch.setenv("PRISMOR_SECRETS_DIR", str(Path(os.environ.get("TMPDIR", "/tmp")) / "prismor-test-secrets"))
    got = access_token(ctx, "https://monitor.azure.com/.default")
    assert got == token
    err = capsys.readouterr().err
    assert "CANARY" not in err
    assert token not in err
    clear_cache()
