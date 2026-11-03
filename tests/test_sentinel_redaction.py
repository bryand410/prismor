"""S-RED: secrets and tokens never reach logs, health, or the spool."""
from __future__ import annotations

import json

from prismor.runtime.sentinel.auth import TokenProvider, clear_cache, redact
from prismor.runtime.sentinel.config import parse
from prismor.runtime.sentinel.delivery import flush_config
from prismor.runtime.sentinel.mapping import to_agent_event_row
from prismor.runtime.sentinel.spool import Spool, spool_path
from tests.sentinel_fake import FakeAzure
from tests.sentinel_support import FakeClock, sink_dict


JWT = "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ4In0.signature"
SECRET = "s3cr3t-VALUE-123"


def setup_function():
    clear_cache()


def _blob(tmp_path, capsys) -> str:
    err = capsys.readouterr().err
    parts = [err]
    for path in tmp_path.rglob("*"):
        if path.is_file():
            parts.append(path.read_text(encoding="utf-8", errors="replace"))
    return "\n".join(parts)


def test_s_red_01_secret_and_jwt_absent(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("PRISMOR_SENTINEL_ALLOW_INSECURE_LOCALHOST", "1")
    monkeypatch.setenv("PRISMOR_HOME", str(tmp_path))
    monkeypatch.setenv("PRISMOR_SENTINEL_DEBUG", "1")
    fake = FakeAzure(token=JWT)
    fake.script("token", [(400, {}, json.dumps({
        "error": "invalid_client",
        "error_description": f"AADSTS7000215 {SECRET}",
        "error_codes": [7000215],
    }).encode()), (200, {}, json.dumps({"access_token": JWT, "expires_in": 3600}).encode())])
    fake.script("ingest", [(500, {"x-ms-error-code": "ServerBusy"}, b"")])
    try:
        cfg = parse(sink_dict(fake))
        try:
            TokenProvider(cfg, clock=FakeClock(0)).get_token()
        except Exception:
            pass
        clear_cache()
        Spool(spool_path(cfg, "events")).append(
            [{"EventId": "evt_" + "ab" * 16, "RuleId": "r"}], now=1)
        flush_config(cfg, clock=FakeClock(1), sleep=lambda _s: None, rand=lambda: 0)
        from prismor.runtime.sentinel.commands import run_status
        run_status(sink_dict(fake), True)
    finally:
        fake.close()
    blob = _blob(tmp_path, capsys)
    assert SECRET not in blob
    assert JWT not in blob


def test_s_red_02_pfx_password_absent(tmp_path, monkeypatch, capsys):
    from datetime import datetime, timedelta, timezone
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives.serialization.pkcs12 import serialize_key_and_certificates
    from cryptography.x509.oid import NameOID
    monkeypatch.setenv("PRISMOR_SENTINEL_ALLOW_INSECURE_LOCALHOST", "1")
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "t")])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder().subject_name(name).issuer_name(name)
        .public_key(key.public_key()).serial_number(1)
        .not_valid_before(now).not_valid_after(now + timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    pfx = tmp_path / "c.pfx"
    password = "pfx-password-ZZ"
    pfx.write_bytes(serialize_key_and_certificates(
        b"n", key, cert, None, serialization.BestAvailableEncryption(password.encode())))
    fake = FakeAzure()
    try:
        cfg = parse(sink_dict(fake, auth={
            "mode": "client_certificate", "client_secret": "", "certificate_file": str(pfx),
            "certificate_password": password, "authority_host": fake.base,
        }))
        try:
            TokenProvider(parse(sink_dict(fake, auth={
                "mode": "client_certificate", "client_secret": "", "certificate_file": str(pfx),
                "certificate_password": "wrong-password", "authority_host": fake.base,
            }))).get_token()
        except Exception:
            pass
        TokenProvider(cfg).get_token()
    finally:
        fake.close()
    assert password not in capsys.readouterr().err


def test_s_red_03_workload_assertion_absent(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("PRISMOR_SENTINEL_ALLOW_INSECURE_LOCALHOST", "1")
    monkeypatch.setenv("PRISMOR_HOME", str(tmp_path))
    assertion = "federated-assertion-VALUE"
    path = tmp_path / "az.jwt"
    path.write_text(assertion, encoding="utf-8")
    fake = FakeAzure()
    try:
        cfg = parse(sink_dict(fake, auth={
            "mode": "workload_identity", "client_secret": "",
            "federated_token_file": str(path), "authority_host": fake.base,
        }))
        TokenProvider(cfg).get_token()
        from prismor.runtime.sentinel import status
        text = json.dumps(status(sink_dict(fake, auth={
            "mode": "workload_identity", "client_secret": "",
            "federated_token_file": str(path), "authority_host": fake.base,
        })))
    finally:
        fake.close()
    assert assertion not in capsys.readouterr().err
    assert assertion not in text


def test_s_red_04_identity_header_absent(monkeypatch, capsys):
    monkeypatch.setenv("PRISMOR_SENTINEL_ALLOW_INSECURE_LOCALHOST", "1")
    header = "identity-header-VALUE"
    fake = FakeAzure()
    monkeypatch.setenv("IDENTITY_ENDPOINT", fake.base + "/msi/token")
    monkeypatch.setenv("IDENTITY_HEADER", header)
    try:
        cfg = parse(sink_dict(fake, auth={"mode": "managed_identity", "client_secret": "",
                                          "tenant_id": "", "client_id": ""}))
        TokenProvider(cfg).get_token()
    finally:
        fake.close()
    assert header not in capsys.readouterr().err


def test_s_red_05_evidence_not_on_the_wire(tmp_path, monkeypatch):
    monkeypatch.setenv("PRISMOR_SENTINEL_ALLOW_INSECURE_LOCALHOST", "1")
    monkeypatch.setenv("PRISMOR_HOME", str(tmp_path))
    secret = "ghp_" + "b" * 36
    fake = FakeAzure()
    try:
        cfg = parse(sink_dict(fake, gzip=False))
        row = to_agent_event_row({
            "rule_id": "r", "evidence": f"token {secret}", "@timestamp": "2026-11-02T00:00:00Z",
        })
        assert secret not in json.dumps(row)
        Spool(spool_path(cfg, "events")).append([row], now=1)
        flush_config(cfg, clock=FakeClock(1), sleep=lambda _s: None, rand=lambda: 0)
    finally:
        fake.close()
    posted = b"".join(item["body"] for item in fake.requests)
    assert secret.encode() not in posted


def test_s_red_06_redact_unit():
    from prismor.runtime.sentinel.auth import register_secret
    register_secret("s3cr3t-VALUE-123")
    assert redact("Bearer " + JWT) == "Bearer ***"
    assert "s3cr3t-VALUE-123" not in redact("https://example.test/?token=s3cr3t-VALUE-123")
