"""Sentinel sink configuration.

The legacy HTTP Data Collector API is rejected. Delivery uses the Logs
Ingestion API only. See docs/sentinel.md.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from urllib.parse import urlsplit

# TODO(verify): DCR immutable ids are documented as opaque strings. The
# ``dcr-`` + 32 hex shape is the common portal form, not a published regex.
# Spec §5.2. Mismatch warns rather than failing.
_DCR_RE = re.compile(r"^dcr-[0-9a-f]{32}$")
_STREAM_RE = re.compile(r"^Custom-[A-Za-z][A-Za-z0-9_]{0,43}$")
_NAME_RE = re.compile(r"^[a-z0-9-]{1,40}$")

# Audiences: Logs Ingestion overview. Authority hosts: Entra national clouds.
CLOUDS: Dict[str, Dict[str, str]] = {
    "public": {
        "authority_host": "https://login.microsoftonline.com",
        "scope": "https://monitor.azure.com/.default",
        # TODO(verify): MI resource with or without a trailing slash.
        # Sent without a slash; S-AUTH-05 pins that.
        "resource": "https://monitor.azure.com",
    },
    "usgov": {
        "authority_host": "https://login.microsoftonline.us",
        "scope": "https://monitor.azure.us/.default",
        "resource": "https://monitor.azure.us",
    },
    "china": {
        "authority_host": "https://login.partner.microsoftonline.cn",
        "scope": "https://monitor.azure.cn/.default",
        "resource": "https://monitor.azure.cn",
    },
}

_KNOWN_SINK_KEYS = {
    "type", "name", "cloud", "endpoint", "dcr_immutable_id", "streams", "auth",
    "delivery", "gzip", "max_batch_bytes", "max_batch_records", "flush_interval_seconds",
    "flush_records", "flush_on_block", "timeout_seconds", "inline_budget_seconds",
    "max_attempts", "spool_max_records", "spool_max_bytes", "spool_max_age_hours",
    "include_evidence", "subject", "subject_salt", "min_severity", "include_audit_allowed",
    "enabled",
}
_LEGACY = ("workspace_id", "shared_key", "customer_id")


class SentinelConfigError(ValueError):
    """The sink config cannot be used. The message is safe to log."""


@dataclass
class SentinelSinkConfig:
    name: str
    endpoint: str
    dcr_immutable_id: str
    auth_mode: str
    cloud: str = "public"
    events_stream: str = "Custom-PrismorAgentEvents"
    inventory_stream: str = "Custom-PrismorAIInventory"
    tenant_id: str = ""
    client_id: str = ""
    client_secret: str = ""
    client_secret_file: str = ""
    client_secret_ref: str = ""
    certificate_file: str = ""
    certificate_password: str = ""
    send_x5c: bool = False
    legacy_rs256: bool = False
    managed_identity_client_id: str = ""
    federated_token_file: str = ""
    authority_host: str = ""
    delivery: str = "auto"
    gzip: bool = True
    max_batch_bytes: int = 950_000
    max_batch_records: int = 500
    flush_interval_seconds: float = 30
    flush_records: int = 200
    flush_on_block: bool = True
    timeout_seconds: float = 3
    inline_budget_seconds: float = 2.0
    max_attempts: int = 5
    spool_max_records: int = 20_000
    spool_max_bytes: int = 52_428_800
    spool_max_age_hours: float = 168
    include_evidence: bool = True
    subject: str = "plain"
    subject_salt: str = ""
    min_severity: str = ""
    include_audit_allowed: bool = True
    enabled: bool = True
    warnings: List[str] = field(default_factory=list)

    @property
    def scope(self) -> str:
        return CLOUDS[self.cloud]["scope"]

    @property
    def resource(self) -> str:
        return CLOUDS[self.cloud]["resource"]

    @property
    def token_authority(self) -> str:
        return (self.authority_host or CLOUDS[self.cloud]["authority_host"]).rstrip("/")


def _https_ok(endpoint: str) -> bool:
    host = (urlsplit(endpoint).hostname or "").lower()
    if endpoint.lower().startswith("https://"):
        return True
    if os.environ.get("PRISMOR_SENTINEL_ALLOW_INSECURE_LOCALHOST") == "1" and host in {"127.0.0.1", "localhost"}:
        return True
    return False


def parse(raw: Dict[str, Any]) -> SentinelSinkConfig:
    """Validate a ``settings.outputs`` sentinel entry. Raises ``SentinelConfigError``."""
    if not isinstance(raw, dict):
        raise SentinelConfigError("sentinel sink must be a mapping")
    warnings: List[str] = []
    for key in _LEGACY:
        if key in raw:
            raise SentinelConfigError(
                "HTTP Data Collector API is deprecated (support ended 2026-09-14); "
                "configure a DCR, see docs/sentinel.md"
            )
    for key in raw:
        if key not in _KNOWN_SINK_KEYS:
            warnings.append(f"unknown sentinel key {key!r} ignored")

    name = str(raw.get("name") or "")
    if not _NAME_RE.match(name):
        raise SentinelConfigError("name is required and must match [a-z0-9-]{1,40}")
    endpoint = str(raw.get("endpoint") or "").strip()
    if not endpoint:
        raise SentinelConfigError("endpoint is required")
    if not _https_ok(endpoint):
        raise SentinelConfigError("endpoint must be https://")
    parts = urlsplit(endpoint)
    normalized = f"{parts.scheme}://{parts.netloc}"
    if endpoint != normalized:
        warnings.append("endpoint path, query, or trailing slash stripped")
    endpoint = normalized

    dcr = str(raw.get("dcr_immutable_id") or "")
    if not dcr:
        raise SentinelConfigError("dcr_immutable_id is required")
    if not _DCR_RE.match(dcr):
        warnings.append("dcr_immutable_id does not match dcr- plus 32 hex chars")

    cloud = str(raw.get("cloud") or "public").lower()
    if cloud not in CLOUDS:
        raise SentinelConfigError("cloud must be public, usgov, or china")
    host = (urlsplit(endpoint).hostname or "").lower()
    if cloud == "public" and host.endswith(".azure.us"):
        warnings.append("cloud/endpoint mismatch")

    streams = raw.get("streams") if isinstance(raw.get("streams"), dict) else {}
    events = streams.get("events", "Custom-PrismorAgentEvents")
    inventory = streams.get("inventory", "Custom-PrismorAIInventory")
    for label, value in (("events", events), ("inventory", inventory)):
        if value in ("", None):
            continue
        if not _STREAM_RE.match(str(value)):
            raise SentinelConfigError(f"stream name {value!r} is not a Custom- stream")

    auth = raw.get("auth") if isinstance(raw.get("auth"), dict) else {}
    mode = str(auth.get("mode") or "")
    if mode not in {"client_secret", "client_certificate", "managed_identity", "workload_identity"}:
        raise SentinelConfigError("auth.mode is required")

    secret = str(auth.get("client_secret") or "")
    secret_file = str(auth.get("client_secret_file") or "")
    secret_ref = str(auth.get("client_secret_ref") or "")
    if mode == "client_secret":
        present = [bool(secret), bool(secret_file), bool(secret_ref)]
        if sum(present) != 1:
            raise SentinelConfigError("exactly one of client_secret, client_secret_file, client_secret_ref")
        if secret and "${" not in secret:
            warnings.append("client_secret literal in policy; use ${ENV}, _file, or _ref")
    if mode == "client_certificate" and not auth.get("certificate_file"):
        raise SentinelConfigError("certificate_file is required")
    tenant = str(auth.get("tenant_id") or "")
    client = str(auth.get("client_id") or "")
    if mode not in {"managed_identity", "workload_identity"} and (not tenant or not client):
        raise SentinelConfigError("tenant_id and client_id are required")

    try:
        batch_bytes = int(raw.get("max_batch_bytes") or 950_000)
    except (TypeError, ValueError):
        raise SentinelConfigError("max_batch_bytes must be an integer")
    if batch_bytes > 1_000_000:
        raise SentinelConfigError("max_batch_bytes cannot exceed 1000000")
    batch_bytes = max(1024, batch_bytes)
    try:
        batch_records = int(raw.get("max_batch_records") or 500)
    except (TypeError, ValueError):
        batch_records = 500
    batch_records = min(10_000, max(1, batch_records))

    delivery = str(os.environ.get("PRISMOR_SENTINEL_DELIVERY") or raw.get("delivery") or "auto")
    if delivery not in {"auto", "system", "background", "inline"}:
        raise SentinelConfigError("delivery must be auto, system, background, or inline")

    cfg = SentinelSinkConfig(
        name=name,
        endpoint=endpoint,
        dcr_immutable_id=dcr,
        auth_mode=mode,
        cloud=cloud,
        events_stream="" if events in ("", None) else str(events),
        inventory_stream="" if inventory in ("", None) else str(inventory),
        tenant_id=tenant,
        client_id=client,
        client_secret=secret,
        client_secret_file=secret_file,
        client_secret_ref=secret_ref,
        certificate_file=str(auth.get("certificate_file") or ""),
        certificate_password=str(auth.get("certificate_password") or ""),
        send_x5c=bool(auth.get("send_x5c") or False),
        legacy_rs256=bool(auth.get("legacy_rs256") or False),
        managed_identity_client_id=str(auth.get("managed_identity_client_id") or ""),
        federated_token_file=str(auth.get("federated_token_file") or ""),
        authority_host=str(auth.get("authority_host") or ""),
        delivery=delivery,
        gzip=bool(raw.get("gzip", True)),
        max_batch_bytes=batch_bytes,
        max_batch_records=batch_records,
        flush_interval_seconds=float(raw.get("flush_interval_seconds") or 30),
        flush_records=int(raw.get("flush_records") or 200),
        flush_on_block=bool(raw.get("flush_on_block", True)),
        timeout_seconds=float(raw.get("timeout_seconds") or 3),
        inline_budget_seconds=float(raw.get("inline_budget_seconds") or 2.0),
        max_attempts=int(raw.get("max_attempts") or 5),
        spool_max_records=int(raw.get("spool_max_records") or 20_000),
        spool_max_bytes=int(raw.get("spool_max_bytes") or 52_428_800),
        spool_max_age_hours=float(raw.get("spool_max_age_hours") or 168),
        include_evidence=bool(raw.get("include_evidence", True)),
        subject=str(raw.get("subject") or "plain"),
        subject_salt=str(raw.get("subject_salt") or ""),
        min_severity=str(raw.get("min_severity") or ""),
        include_audit_allowed=bool(raw.get("include_audit_allowed", True)),
        enabled=bool(raw.get("enabled", True)),
        warnings=warnings,
    )
    return cfg
