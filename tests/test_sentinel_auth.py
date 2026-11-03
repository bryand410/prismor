"""S-AUTH: Entra and managed-identity flows against FakeAzure."""
from __future__ import annotations

import json
import uuid
from base64 import urlsafe_b64decode
from datetime import datetime, timedelta, timezone
from urllib.parse import parse_qs

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.serialization.pkcs12 import serialize_key_and_certificates
from cryptography.x509.oid import NameOID

from prismor.runtime.sentinel.auth import AuthError, TokenProvider, clear_cache
from prismor.runtime.sentinel.config import SentinelConfigError, parse
from tests.sentinel_fake import FakeAzure
from tests.sentinel_support import FakeClock, sink_dict


def setup_function():
    clear_cache()


def _b64(segment: str) -> bytes:
    pad = "=" * (-len(segment) % 4)
    return urlsafe_b64decode(segment + pad)


def _pem_cert(key, password=None):
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "prismor-test")])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=2))
        .sign(key, hashes.SHA256())
    )
    return cert


def _write_pem(path, key, cert):
    blob = key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    ) + cert.public_bytes(serialization.Encoding.PEM)
    path.write_bytes(blob)


def test_s_auth_01_client_secret(monkeypatch):
    monkeypatch.setenv("PRISMOR_SENTINEL_ALLOW_INSECURE_LOCALHOST", "1")
    fake = FakeAzure(token="access-token-1")
    try:
        cfg = parse(sink_dict(fake))
        token = TokenProvider(cfg, clock=FakeClock(0)).get_token()
    finally:
        fake.close()
    assert token == "access-token-1"
    posts = [item for item in fake.requests if item["path"].endswith("/oauth2/v2.0/token")]
    assert len(posts) == 1
    assert posts[0]["form"] == {
        "grant_type": "client_credentials",
        "client_id": "client-1",
        "client_secret": "s3cr3t-VALUE-123",
        "scope": "https://monitor.azure.com/.default",
    }


def test_s_auth_02_certificate_ps256(tmp_path, monkeypatch):
    monkeypatch.setenv("PRISMOR_SENTINEL_ALLOW_INSECURE_LOCALHOST", "1")
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    cert = _pem_cert(key)
    pem = tmp_path / "client.pem"
    _write_pem(pem, key, cert)
    fake = FakeAzure(token="cert-token")
    try:
        cfg = parse(sink_dict(fake, auth={
            "mode": "client_certificate", "certificate_file": str(pem),
            "client_secret": "", "tenant_id": "tenant-1", "client_id": "client-1",
            "authority_host": fake.base,
        }))
        assert TokenProvider(cfg, clock=FakeClock(1_700_000_000)).get_token() == "cert-token"
    finally:
        fake.close()
    form = [item for item in fake.requests if item["form"]][-1]["form"]
    assert form["client_assertion_type"] == "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
    assert "client_secret" not in form
    header_b, claims_b, sig_b = form["client_assertion"].split(".")
    header = json.loads(_b64(header_b))
    claims = json.loads(_b64(claims_b))
    assert header["alg"] == "PS256" and header["typ"] == "JWT"
    digest = hashes.Hash(hashes.SHA256())
    digest.update(cert.public_bytes(serialization.Encoding.DER))
    thumb = digest.finalize()
    import base64
    assert header["x5t#S256"] == base64.urlsafe_b64encode(thumb).rstrip(b"=").decode()
    assert claims["aud"] == f"{fake.base}/tenant-1/oauth2/v2.0/token"
    assert claims["iss"] == claims["sub"] == "client-1"
    uuid.UUID(claims["jti"])
    assert claims["exp"] - claims["nbf"] == 600
    key.public_key().verify(
        _b64(sig_b),
        f"{header_b}.{claims_b}".encode("ascii"),
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.DIGEST_LENGTH),
        hashes.SHA256(),
    )


def test_s_auth_03_pfx_and_wrong_password(tmp_path, monkeypatch):
    monkeypatch.setenv("PRISMOR_SENTINEL_ALLOW_INSECURE_LOCALHOST", "1")
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    cert = _pem_cert(key)
    pfx = tmp_path / "client.pfx"
    pfx.write_bytes(serialize_key_and_certificates(
        b"prismor", key, cert, None, serialization.BestAvailableEncryption(b"hunter2")))
    fake = FakeAzure(token="pfx-token")
    try:
        cfg = parse(sink_dict(fake, auth={
            "mode": "client_certificate", "certificate_file": str(pfx),
            "certificate_password": "hunter2", "client_secret": "",
            "tenant_id": "tenant-1", "client_id": "client-1", "authority_host": fake.base,
        }))
        assert TokenProvider(cfg).get_token() == "pfx-token"
        clear_cache()
        bad = parse(sink_dict(fake, auth={
            "mode": "client_certificate", "certificate_file": str(pfx),
            "certificate_password": "hunter2-wrong", "client_secret": "",
            "tenant_id": "tenant-1", "client_id": "client-1", "authority_host": fake.base,
        }))
        with pytest.raises(SentinelConfigError) as exc:
            TokenProvider(bad).get_token()
    finally:
        fake.close()
    assert "hunter2" not in str(exc.value)


def test_s_auth_04_ec_key_rejected(tmp_path, monkeypatch):
    monkeypatch.setenv("PRISMOR_SENTINEL_ALLOW_INSECURE_LOCALHOST", "1")
    key = ec.generate_private_key(ec.SECP256R1())
    cert = _pem_cert(key)
    pem = tmp_path / "ec.pem"
    _write_pem(pem, key, cert)
    fake = FakeAzure()
    try:
        cfg = parse(sink_dict(fake, auth={
            "mode": "client_certificate", "certificate_file": str(pem), "client_secret": "",
            "tenant_id": "tenant-1", "client_id": "client-1", "authority_host": fake.base,
        }))
        with pytest.raises(SentinelConfigError, match="RSA required"):
            TokenProvider(cfg).get_token()
    finally:
        fake.close()


def test_s_auth_05_imds(monkeypatch):
    monkeypatch.setenv("PRISMOR_SENTINEL_ALLOW_INSECURE_LOCALHOST", "1")
    fake = FakeAzure(token="mi-token")
    monkeypatch.setenv("PRISMOR_SENTINEL_IMDS_ENDPOINT", fake.base)
    monkeypatch.delenv("IDENTITY_ENDPOINT", raising=False)
    monkeypatch.delenv("IDENTITY_HEADER", raising=False)
    try:
        cfg = parse(sink_dict(fake, auth={"mode": "managed_identity", "client_secret": "",
                                          "tenant_id": "", "client_id": ""}))
        assert TokenProvider(cfg).get_token() == "mi-token"
        got = [item for item in fake.requests if item["method"] == "GET"][-1]
        query = parse_qs(got["query"])
        assert got["headers"]["Metadata"] == "true"
        assert query["resource"] == ["https://monitor.azure.com"]
        assert query["api-version"] == ["2018-02-01"]
        assert "client_id" not in query
        clear_cache()
        cfg2 = parse(sink_dict(fake, auth={
            "mode": "managed_identity", "client_secret": "", "tenant_id": "", "client_id": "",
            "managed_identity_client_id": "user-assigned",
        }))
        TokenProvider(cfg2).get_token()
        query2 = parse_qs([item for item in fake.requests if item["method"] == "GET"][-1]["query"])
        assert query2["client_id"] == ["user-assigned"]
    finally:
        fake.close()


def test_s_auth_06_app_service_not_imds(monkeypatch):
    monkeypatch.setenv("PRISMOR_SENTINEL_ALLOW_INSECURE_LOCALHOST", "1")
    fake = FakeAzure(token="app-token")
    body = json.dumps({"access_token": "app-token", "expires_on": "4102444800"}).encode()
    fake.script("msi", [(200, {"Content-Type": "application/json"}, body)])
    monkeypatch.setenv("IDENTITY_ENDPOINT", fake.base + "/msi/token")
    monkeypatch.setenv("IDENTITY_HEADER", "identity-header-value")
    try:
        cfg = parse(sink_dict(fake, auth={"mode": "managed_identity", "client_secret": "",
                                          "tenant_id": "", "client_id": ""}))
        assert TokenProvider(cfg, clock=FakeClock(1_700_000_000)).get_token() == "app-token"
    finally:
        fake.close()
    paths = [item["path"] for item in fake.requests]
    assert any(path.endswith("/msi/token") for path in paths)
    assert not any("metadata/identity" in path for path in paths)
    got = fake.requests[0]
    headers = {key.lower(): value for key, value in got["headers"].items()}
    assert headers.get("x-identity-header") == "identity-header-value"
    assert "api-version=2019-08-01" in got["query"]


def test_s_auth_07_workload_rereads_file(tmp_path, monkeypatch):
    monkeypatch.setenv("PRISMOR_SENTINEL_ALLOW_INSECURE_LOCALHOST", "1")
    token_file = tmp_path / "azure-token"
    token_file.write_text("assertion-one", encoding="utf-8")
    fake = FakeAzure(token="wl-token")
    try:
        cfg = parse(sink_dict(fake, auth={
            "mode": "workload_identity", "client_secret": "",
            "federated_token_file": str(token_file),
            "tenant_id": "tenant-1", "client_id": "client-1", "authority_host": fake.base,
        }))
        provider = TokenProvider(cfg, clock=FakeClock(0))
        provider.get_token(force=True)
        token_file.write_text("assertion-two", encoding="utf-8")
        provider.get_token(force=True)
    finally:
        fake.close()
    forms = [item["form"]["client_assertion"] for item in fake.requests if item["form"]]
    assert forms == ["assertion-one", "assertion-two"]


def test_s_auth_08_workload_missing_file(tmp_path, monkeypatch):
    monkeypatch.setenv("PRISMOR_SENTINEL_ALLOW_INSECURE_LOCALHOST", "1")
    missing = tmp_path / "nope"
    fake = FakeAzure()
    try:
        cfg = parse(sink_dict(fake, auth={
            "mode": "workload_identity", "client_secret": "",
            "federated_token_file": str(missing),
            "tenant_id": "tenant-1", "client_id": "client-1", "authority_host": fake.base,
        }))
        with pytest.raises(AuthError) as exc:
            TokenProvider(cfg).get_token()
    finally:
        fake.close()
    assert exc.value.code == "auth_error"
    assert str(missing) in str(exc.value)


def test_s_auth_09_cache_hit(monkeypatch):
    monkeypatch.setenv("PRISMOR_SENTINEL_ALLOW_INSECURE_LOCALHOST", "1")
    fake = FakeAzure()
    try:
        cfg = parse(sink_dict(fake))
        provider = TokenProvider(cfg, clock=FakeClock(0))
        assert provider.get_token() == provider.get_token()
    finally:
        fake.close()
    assert len([item for item in fake.requests if item["path"].endswith("/token")]) == 1


def test_s_auth_10_refresh_window(monkeypatch):
    monkeypatch.setenv("PRISMOR_SENTINEL_ALLOW_INSECURE_LOCALHOST", "1")
    fake = FakeAzure()
    clock = FakeClock(0)
    try:
        cfg = parse(sink_dict(fake))
        provider = TokenProvider(cfg, clock=clock)
        provider.get_token()
        clock.now = 3299
        provider.get_token()
        assert len(fake.requests) == 1
        clock.now = 3301
        provider.get_token()
        assert len(fake.requests) == 2
    finally:
        fake.close()


def test_s_auth_11_short_lived_token(monkeypatch):
    monkeypatch.setenv("PRISMOR_SENTINEL_ALLOW_INSECURE_LOCALHOST", "1")
    fake = FakeAzure()
    fake.script("token", [(200, {}, json.dumps({
        "access_token": "short-lived", "expires_in": 600, "token_type": "Bearer",
    }).encode())])
    clock = FakeClock(0)
    try:
        cfg = parse(sink_dict(fake))
        provider = TokenProvider(cfg, clock=clock)
        assert provider.get_token() == "short-lived"
        clock.now = 299
        provider.get_token()
        assert len([item for item in fake.requests if item["form"]]) == 1
        clock.now = 300
        provider.get_token()
        assert len([item for item in fake.requests if item["form"]]) == 2
    finally:
        fake.close()


def test_s_auth_14_invalid_secret_redacted(monkeypatch):
    monkeypatch.setenv("PRISMOR_SENTINEL_ALLOW_INSECURE_LOCALHOST", "1")
    fake = FakeAzure()
    fake.script("token", [(400, {}, json.dumps({
        "error": "invalid_client",
        "error_description": "AADSTS7000215 secret s3cr3t-VALUE-123",
        "error_codes": [7000215],
    }).encode())])
    try:
        cfg = parse(sink_dict(fake))
        with pytest.raises(AuthError) as exc:
            TokenProvider(cfg).get_token()
    finally:
        fake.close()
    assert "7000215" in exc.value.code
    assert "s3cr3t-VALUE-123" not in str(exc.value)


def test_s_auth_15_cache_key_isolation(monkeypatch):
    monkeypatch.setenv("PRISMOR_SENTINEL_ALLOW_INSECURE_LOCALHOST", "1")
    fake = FakeAzure(token="token-a")
    try:
        one = parse(sink_dict(fake, auth={"client_id": "client-a"}))
        TokenProvider(one, clock=FakeClock(0)).get_token()
        fake.token = "token-b"
        two = parse(sink_dict(fake, name="hmlr-sentinel-b", auth={"client_id": "client-b"}))
        assert TokenProvider(two, clock=FakeClock(0)).get_token() == "token-b"
        assert TokenProvider(one, clock=FakeClock(0)).get_token() == "token-a"
    finally:
        fake.close()
    assert len([item for item in fake.requests if item["path"].endswith("/token")]) == 2
