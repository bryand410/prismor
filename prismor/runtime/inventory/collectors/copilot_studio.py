"""Copilot Studio inventory.

Option A is the Power Platform inventory API (delegated user). A 403 — the
documented response for a service principal — yields a diagnostic and, when
``api`` is ``auto``, falls through to Option B (Dataverse per environment).

``botcomponent.data`` and ``iconbase64`` are parsed in memory and never stored.
Component type and authentication enums are the Dataverse entity reference
(bot, botcomponent) as published by Microsoft.
"""
from __future__ import annotations

import json
from typing import Any, Dict, Iterable, List, Optional, Tuple
from urllib.parse import quote

from prismor.runtime.inventory.auth.entra import AuthError, access_token
from prismor.runtime.inventory.context import ScanContext
from prismor.runtime.inventory.ids import mcp_entity_key
from prismor.runtime.inventory.schema import (
    Governance, InventoryRecord, Location, diagnostic,
)

SURFACE = "lowcode.copilot_studio"
REQUIRES = {"os": ["windows", "darwin", "linux"], "auth": "entra", "extras": []}

INVENTORY_URL = "https://api.powerplatform.com/resourcequery/resources/query?api-version=2024-10-01"
# BAP admin environment list. The api-version pin was not re-fetched from a
# doc page in this change (UNVERIFIED_API_VERSION).
BAP_ENVIRONMENTS = (
    "https://api.bap.microsoft.com/providers/Microsoft.BusinessAppPlatform/"
    "scopes/admin/environments?api-version=2021-04-01"
)

# https://learn.microsoft.com/en-us/power-apps/developer/data-platform/reference/entities/bot
AUTH_MODE = {
    0: "Unspecified", 1: "None", 2: "Integrated",
    3: "Custom Entra ID", 4: "Generic OAuth2",
}
ACCESS_POLICY = {
    0: "Any", 1: "Agent readers", 2: "Group membership", 3: "Any (multi-tenant)",
}
# https://learn.microsoft.com/en-us/power-apps/developer/data-platform/reference/entities/botcomponent
COMPONENT_TYPE = {
    0: "Topic", 1: "Skill", 2: "Bot variable", 3: "Bot entity", 4: "Dialog",
    5: "Trigger", 6: "Language understanding", 7: "Language generation",
    8: "Dialog schema", 9: "Topic (V2)", 10: "Bot translations (V2)",
    11: "Bot entity (V2)", 12: "Bot variable (V2)", 13: "Skill (V2)",
    14: "Bot File Attachment", 15: "Custom GPT", 16: "Knowledge Source",
    17: "External Trigger", 18: "Copilot Settings", 19: "Test Case",
    20: "Custom Metric Definition",
}

_BOT_SELECT = (
    "botid,name,schemaname,statecode,statuscode,publishedon,modifiedon,"
    "authenticationmode,authenticationtrigger,accesscontrolpolicy,language"
)


def _settings(ctx: ScanContext) -> Dict[str, Any]:
    return dict(ctx.copilot_studio or {})


def _api_mode(ctx: ScanContext) -> str:
    return str(_settings(ctx).get("api") or "auto").lower()


def _wanted_envs(ctx: ScanContext) -> List[str]:
    raw = _settings(ctx).get("environments") or []
    return [str(item) for item in raw if str(item)]


def _token(ctx: ScanContext, scope: str) -> str:
    return access_token(ctx, scope)


def _get(ctx: ScanContext, url: str, token: str) -> Tuple[int, Any]:
    result = ctx.http(
        "GET", url,
        headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
        timeout=ctx.request_timeout,
    )
    if result.status != 200:
        return result.status, None
    try:
        return result.status, result.json()
    except ValueError:
        return result.status, None


def _post(ctx: ScanContext, url: str, token: str, body: Dict[str, Any]) -> Tuple[int, Any]:
    result = ctx.http(
        "POST", url,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
            "Content-Type": "application/json",
        },
        body=json.dumps(body).encode("utf-8"),
        timeout=ctx.request_timeout,
    )
    if result.status != 200:
        return result.status, None
    try:
        return result.status, result.json()
    except ValueError:
        return result.status, None


def _owner_hash(ctx: ScanContext, raw: Any) -> str:
    if isinstance(raw, dict):
        raw = raw.get("fullname") or raw.get("id") or raw.get("ownerid") or ""
    text = str(raw or "").strip()
    if not text:
        return ""
    return ctx.user_token(text)


def _governed(ctx: ScanContext, environment_id: str) -> Governance:
    enrolled = environment_id and environment_id in set(ctx.governed_environments)
    return Governance(
        managed=bool(enrolled),
        governed_by="prismor-copilot-studio-provider" if enrolled else "none",
        coverable=True,
    )


def _agent_record(
    ctx: ScanContext,
    *,
    agent_id: str,
    name: str,
    environment_id: str,
    environment_name: str,
    source_api: str,
    attrs: Dict[str, Any],
) -> InventoryRecord:
    return InventoryRecord(
        kind="lowcode_agent",
        surface="lowcode",
        source=SURFACE,
        product="copilot-studio",
        vendor="Microsoft",
        name=name or agent_id,
        entity_key="cps:" + agent_id,
        location=Location(
            os=ctx.os_name,
            scope="tenant",
            tenant_id=str(_settings(ctx).get("tenant_id") or ctx.auth.get("tenant") or "") or None,
            environment_id=environment_id or None,
        ),
        governance=_governed(ctx, environment_id),
        attributes={
            "environment_id": environment_id,
            "environment_name": environment_name,
            "source_api": source_api,
            **attrs,
        },
        evidence=[{"type": "api", "ref": source_api}],
    )


def _from_inventory_row(ctx: ScanContext, row: Dict[str, Any]) -> Optional[InventoryRecord]:
    if str(row.get("type") or "") != "microsoft.copilotstudio/agents":
        return None
    props = row.get("properties") if isinstance(row.get("properties"), dict) else {}
    agent_id = str(props.get("botId") or row.get("name") or row.get("id") or "")
    if not agent_id:
        return None
    environment_id = str(props.get("environmentId") or "")
    wanted = _wanted_envs(ctx)
    if wanted and environment_id not in wanted:
        return None
    published = props.get("lastPublishedAt")
    attrs = {
        "created_at": props.get("createdAt"),
        "modified_at": props.get("lastModifiedAt"),
        "published_at": published,
        "state": props.get("state"),
        "is_managed_solution": props.get("isManaged"),
        "entra_app_id": props.get("entraAppId") or "",
        "entra_agent_id": props.get("entraAgentId") or "",
        "schema_name": props.get("schemaName") or "",
        "owner": _owner_hash(ctx, props.get("createdBy") or props.get("ownerId")),
        "components": {},
        "unpublished": published in (None, ""),
    }
    # Identity fields are ids, not secrets. Drop empties so the record stays small.
    return _agent_record(
        ctx, agent_id=agent_id,
        name=str(props.get("displayName") or row.get("name") or agent_id),
        environment_id=environment_id,
        environment_name=str(props.get("environmentName") or ""),
        source_api="inventory",
        attrs=attrs,
    )


def _inventory_pages(ctx: ScanContext, token: str) -> Tuple[List[InventoryRecord], int]:
    records: List[InventoryRecord] = []
    skip = 0
    skip_token = ""
    status = 200
    for _page in range(50):
        if len(records) >= ctx.record_cap:
            break
        body = {
            "TableName": "PowerPlatformResources",
            "Clauses": [
                {"$type": "where", "FieldName": "type", "Operator": "in~",
                 "Values": ["'microsoft.copilotstudio/agents'"]},
                {"$type": "take", "TakeCount": 1000},
            ],
            "Options": {"Top": 1000, "Skip": skip, "SkipToken": skip_token},
        }
        status, payload = _post(ctx, INVENTORY_URL, token, body)
        if status != 200 or not isinstance(payload, dict):
            return records, status
        data = payload.get("data") or []
        if not isinstance(data, list) or not data:
            break
        for row in data:
            if isinstance(row, dict):
                record = _from_inventory_row(ctx, row)
                if record is not None:
                    records.append(record)
        skip_token = str(payload.get("skipToken") or "")
        count = int(payload.get("count") or len(data))
        skip += count
        if not skip_token and count < 1000:
            break
        if not skip_token and count >= 1000:
            # Offset paging when the service does not return a continuation token.
            continue
    return records, status


def _walk_kinds(node: Any, acc: Dict[str, Any]) -> None:
    """Pull kinds and ids out of component YAML/JSON. Do not keep the tree."""
    if isinstance(node, dict):
        for key, value in node.items():
            lowered = str(key).lower()
            if lowered in {"connectionreference", "connectionreferences"}:
                acc["maker_credentials"] = True
            if lowered in {"runas", "credentialtype"} and str(value).lower() in {"maker", "embedded"}:
                acc["maker_credentials"] = True
            if lowered in {"url", "serverurl", "endpoint"} and isinstance(value, str) and value.startswith("http"):
                if "mcp" in value.lower() or "mcp" in lowered:
                    acc["mcp_urls"].append(value)
            if lowered in {"kind", "knowledgesourcekind", "type"} and isinstance(value, str):
                acc["knowledge_kinds"].append(value)
            _walk_kinds(value, acc)
    elif isinstance(node, list):
        for item in node:
            _walk_kinds(item, acc)


def _parse_component_data(raw: str) -> Dict[str, Any]:
    acc: Dict[str, Any] = {"maker_credentials": False, "mcp_urls": [], "knowledge_kinds": []}
    if not raw or not isinstance(raw, str):
        return acc
    parsed: Any = None
    try:
        import yaml
        parsed = yaml.safe_load(raw)
    except Exception:
        parsed = None
    if not isinstance(parsed, (dict, list)):
        try:
            parsed = json.loads(raw)
        except ValueError:
            parsed = None
    if isinstance(parsed, (dict, list)):
        _walk_kinds(parsed, acc)
    return acc


def _apply_component_signals(attrs: Dict[str, Any], components: List[Dict[str, Any]]) -> List[str]:
    """Fold component summaries into ``attrs``. Returns redacted MCP urls."""
    from prismor.runtime.discover import redact_url
    topics = 0
    knowledge: List[str] = []
    connectors: List[str] = []
    triggers: List[str] = []
    mcp_urls: List[str] = []
    for component in components:
        kind = component.get("kind") or ""
        if kind in {"Topic", "Topic (V2)"}:
            topics += 1
        if kind == "Knowledge Source":
            knowledge.extend(component.get("knowledge_kinds") or ["knowledge"])
            if component.get("web"):
                attrs["web_knowledge"] = True
        if kind in {"External Trigger", "Trigger"} and component.get("autonomous"):
            triggers.append(kind)
            attrs["autonomous_trigger"] = True
        if component.get("maker_credentials"):
            connectors.append(component.get("name") or "connector")
            attrs["maker_credentials"] = True
        mcp_urls.extend(redact_url(url) for url in (component.get("mcp_urls") or []))
    attrs["components"] = {
        "topics": topics,
        "knowledge_kinds": sorted(set(knowledge))[:20],
        "connectors": sorted(set(connectors))[:20],
        "mcp_urls": sorted(set(mcp_urls))[:20],
        "triggers": sorted(set(triggers))[:20],
    }
    return sorted(set(mcp_urls))


def _summarise_component(row: Dict[str, Any]) -> Dict[str, Any]:
    try:
        type_code = int(row.get("componenttype"))
    except (TypeError, ValueError):
        type_code = -1
    kind = COMPONENT_TYPE.get(type_code, f"unknown:{type_code}")
    parsed = _parse_component_data(str(row.get("data") or ""))
    blob = " ".join(str(item) for item in parsed["knowledge_kinds"]).lower()
    web = kind == "Knowledge Source" and any(
        token in blob for token in ("web", "site", "public", "search")
    )
    autonomous = type_code == 17 or (type_code == 5 and "autonomous" in str(row.get("name") or "").lower())
    return {
        "kind": kind,
        "name": str(row.get("name") or ""),
        "knowledge_kinds": parsed["knowledge_kinds"],
        "maker_credentials": parsed["maker_credentials"] or "connector" in kind.lower(),
        "mcp_urls": parsed["mcp_urls"],
        "web": web,
        "autonomous": autonomous,
    }


def _dataverse(ctx: ScanContext) -> Iterable[InventoryRecord]:
    try:
        token = _token(ctx, "https://api.bap.microsoft.com/.default")
    except AuthError as exc:
        yield diagnostic(SURFACE, error_code="auth", hint=exc.code, surface="lowcode")
        return
    status, payload = _get(ctx, BAP_ENVIRONMENTS, token)
    if status == 401:
        yield diagnostic(SURFACE, error_code="auth", hint="http_401", surface="lowcode")
        return
    if status == 403:
        yield diagnostic(SURFACE, error_code="http_403",
                         hint="Dataverse environment list was forbidden for this identity",
                         surface="lowcode")
        return
    if status != 200 or not isinstance(payload, dict):
        yield diagnostic(SURFACE, error_code=f"http_{status}", hint="environment list failed", surface="lowcode")
        return
    environments = payload.get("value") or []
    wanted = set(_wanted_envs(ctx))
    for env in environments:
        if not isinstance(env, dict):
            continue
        props = env.get("properties") if isinstance(env.get("properties"), dict) else {}
        env_id = str(env.get("name") or "")
        if wanted and env_id not in wanted:
            continue
        meta = props.get("linkedEnvironmentMetadata") if isinstance(props.get("linkedEnvironmentMetadata"), dict) else {}
        instance = str(meta.get("instanceUrl") or "").rstrip("/")
        env_name = str(props.get("displayName") or "")
        if not instance:
            continue
        try:
            org_token = _token(ctx, instance + "/.default")
        except AuthError as exc:
            yield diagnostic(SURFACE, error_code="auth", hint=exc.code, surface="lowcode", name=env_id)
            continue
        yield from _bots(ctx, instance, org_token, env_id, env_name)


def _bots(ctx: ScanContext, instance: str, token: str, env_id: str, env_name: str) -> Iterable[InventoryRecord]:
    url = f"{instance}/api/data/v9.2/bots?$select={_BOT_SELECT}"
    while url and ctx.record_cap:
        status, payload = _get(ctx, url, token)
        if status in (401, 403):
            yield diagnostic(SURFACE, error_code="auth" if status == 401 else "http_403",
                             hint=f"http_{status}", surface="lowcode", name=env_id)
            return
        if status != 200 or not isinstance(payload, dict):
            yield diagnostic(SURFACE, error_code=f"http_{status}", hint="bot list failed",
                             surface="lowcode", name=env_id)
            return
        for bot in payload.get("value") or []:
            if isinstance(bot, dict):
                yield from _one_bot(ctx, instance, token, env_id, env_name, bot)
        url = str(payload.get("@odata.nextLink") or "")


def _one_bot(ctx: ScanContext, instance: str, token: str, env_id: str, env_name: str,
             bot: Dict[str, Any]) -> Iterable[InventoryRecord]:
    agent_id = str(bot.get("botid") or "")
    if not agent_id:
        return []
    try:
        auth_code = int(bot.get("authenticationmode"))
    except (TypeError, ValueError):
        auth_code = -1
    try:
        access_code = int(bot.get("accesscontrolpolicy"))
    except (TypeError, ValueError):
        access_code = -1
    auth_label = AUTH_MODE.get(auth_code, "")
    access_label = ACCESS_POLICY.get(access_code, "")
    published = bot.get("publishedon")
    filter_value = quote(agent_id)
    comp_url = (
        f"{instance}/api/data/v9.2/botcomponents"
        f"?$filter=_parentbotid_value eq {filter_value}"
        "&$select=botcomponentid,componenttype,name,schemaname,data"
    )
    summaries: List[Dict[str, Any]] = []
    status, payload = _get(ctx, comp_url, token)
    if status == 200 and isinstance(payload, dict):
        for row in payload.get("value") or []:
            if isinstance(row, dict):
                summaries.append(_summarise_component(row))
    elif status in (401, 403):
        yield diagnostic(SURFACE, error_code="http_403" if status == 403 else "auth",
                         hint="bot component list was not readable", surface="lowcode", name=agent_id)
    attrs: Dict[str, Any] = {
        "created_at": None,
        "modified_at": bot.get("modifiedon"),
        "published_at": published,
        "state": "Active" if bot.get("statecode") == 0 else "Inactive" if bot.get("statecode") == 1 else bot.get("statecode"),
        "auth_mode": auth_label,
        "access_policy": access_label,
        "is_managed_solution": None,
        "entra_app_id": "",
        "entra_agent_id": "",
        "schema_name": bot.get("schemaname") or "",
        "owner": "",
        "no_auth": auth_code in (0, 1),
        "shared_tenant_wide": access_code in (0, 3),
        "unpublished": not published,
    }
    mcp_urls = _apply_component_signals(attrs, summaries)
    record = _agent_record(
        ctx, agent_id=agent_id, name=str(bot.get("name") or agent_id),
        environment_id=env_id, environment_name=env_name, source_api="dataverse", attrs=attrs,
    )
    yield record
    for mcp_url in mcp_urls:
        from prismor.runtime.discover import redact_url
        redacted = redact_url(mcp_url)
        yield InventoryRecord(
            kind="mcp_server",
            surface="lowcode",
            source=SURFACE,
            product="copilot-studio",
            vendor="Microsoft",
            name=redacted,
            entity_key=mcp_entity_key([], mcp_url),
            location=Location(os=ctx.os_name, scope="tenant", environment_id=env_id,
                              tenant_id=record.location.tenant_id),
            governance=_governed(ctx, env_id),
            attributes={"url": redacted, "remote": True, "transport": "http", "parent": "cps:" + agent_id},
            related=[{"entity_key": "cps:" + agent_id, "kind": "lowcode_agent", "reason": "mcp tool"}],
        )


def collect(ctx: ScanContext) -> Iterable[InventoryRecord]:
    mode = _api_mode(ctx)
    if ctx.dry_run:
        yield diagnostic(
            SURFACE, error_code="dry_run", surface="lowcode",
            hint=f"would POST {INVENTORY_URL} (api={mode}); on 403, GET Dataverse bots",
        )
        return
    inventory_status = 0
    if mode in {"inventory", "auto"}:
        try:
            token = _token(ctx, "https://api.powerplatform.com/.default")
        except AuthError as exc:
            yield diagnostic(SURFACE, error_code="auth", hint=exc.code, surface="lowcode")
            if mode == "inventory":
                return
            token = ""
        else:
            records, inventory_status = _inventory_pages(ctx, token)
            if inventory_status == 200:
                yield from records
                return
            if inventory_status == 401:
                yield diagnostic(SURFACE, error_code="auth", hint="http_401", surface="lowcode")
                return
            if inventory_status == 403:
                yield diagnostic(
                    SURFACE, error_code="http_403", surface="lowcode",
                    hint="inventory API rejected this identity; retry with --api dataverse",
                )
                if mode == "inventory":
                    return
            elif inventory_status and inventory_status != 200:
                yield diagnostic(SURFACE, error_code=f"http_{inventory_status}",
                                 hint="inventory query failed", surface="lowcode")
                if mode == "inventory":
                    return
    if mode in {"dataverse", "auto"}:
        yield from _dataverse(ctx)
