"""Entra and managed-identity tokens for the Logs Ingestion API.

Stdlib HTTP plus ``cryptography``. Tokens stay in memory and are scrubbed
from every error string by ``redact``.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import time
import uuid
from dataclasses import dataclass
from typing import Any, Callable, Dict, Optional, Tuple
from urllib.parse import urlencode

from prismor.runtime.sentinel.config import CLOUDS, SentinelConfigError, SentinelSinkConfig

_SECRETS: list = []
Transport = Callable[..., Tuple[int, Dict[str, str], bytes]]


def register_secret(value: str) -> None:
    if value and value not in _SECRETS:
        _SECRETS.append(value)


def redact(text: str) -> str:
    """Replace registered secrets and JWT-shaped strings with ``***``."""
    import re
    out = str(text or "")
    for secret in sorted(_SECRETS, key=len, reverse=True):
        # Short values would rewrite ordinary JSON. Real secrets are longer.
        if secret and len(secret) >= 8:
            out = out.replace(secret, "***")
    return re.sub(r"eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]*", "***", out)


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _default_transport(method: str, url: str, headers: Dict[str, str], body: Optional[bytes],
                       timeout: float) -> Tuple[int, Dict[str, str], bytes]:
    import urllib.error
    import urllib.request

    class _NoRedirect(urllib.request.HTTPRedirectHandler):
        """IMDS must not be followed off the link-local address."""

        def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: A002
            return None

    opener = urllib.request.build_opener(_NoRedirect)
    from prismor.runtime.http_ua import user_agent
    sent = dict(headers or {})
    sent.setdefault("User-Agent", user_agent())
    request = urllib.request.Request(url, data=body, headers=sent, method=method)
    try:
        with opener.open(request, timeout=timeout) as resp:  # nosec B310
            return int(resp.status), {k: v for k, v in resp.headers.items()}, resp.read()
    except urllib.error.HTTPError as exc:
        raw = exc.read() if exc.fp else b""
        hdrs = {k: v for k, v in (exc.headers.items() if exc.headers else [])}
        return int(exc.code), hdrs, raw


class AuthError(Exception):
    def __init__(self, code: str, message: str = "") -> None:
        self.code = code
        safe = redact(message or code)[:300]
        super().__init__(safe)


@dataclass
class Token:
    value: str
    expires_at: float


class TokenCache:
    def __init__(self) -> None:
        self._items: Dict[tuple, Token] = {}

    def get(self, key: tuple, now: float) -> Optional[str]:
        item = self._items.get(key)
        if item and now < item.expires_at:
            return item.value
        return None

    def put(self, key: tuple, value: str, expires_at: float) -> None:
        register_secret(value)
        self._items[key] = Token(value, expires_at)

    def invalidate(self, key: tuple) -> None:
        self._items.pop(key, None)


_CACHE = TokenCache()


def _refresh_at(now: float, expires_in: float) -> float:
    # S-AUTH-10 pins a 3600s token to refresh at 3300s, and S-AUTH-11 pins a
    # 600s token to refresh at 300s. Both are a 300s lead. A 10% lead on a
    # one-hour token would be 360s and would fail S-AUTH-10.
    return now + expires_in - 300.0


def _parse_expiry(payload: Dict[str, Any], now: float) -> float:
    if payload.get("expires_in") not in (None, ""):
        return float(payload["expires_in"])
    expires_on = payload.get("expires_on")
    if expires_on not in (None, ""):
        return max(0.0, float(expires_on) - now)
    return 3600.0


def _form_post(transport: Transport, url: str, fields: Dict[str, str], timeout: float) -> Dict[str, Any]:
    status, _headers, body = transport(
        "POST", url, {"Content-Type": "application/x-www-form-urlencoded"},
        urlencode(fields).encode("utf-8"), timeout,
    )
    try:
        payload = json.loads(body.decode("utf-8") or "{}")
    except ValueError:
        payload = {}
    if not isinstance(payload, dict):
        payload = {}
    if status != 200:
        description = redact(str(payload.get("error_description") or payload.get("error") or ""))
        code = str(payload.get("error_codes") or payload.get("error") or status)
        raise AuthError(str(code), description)
    token = str(payload.get("access_token") or "")
    if not token:
        raise AuthError("no_access_token", "token response had no access_token")
    register_secret(token)
    return payload


def _load_secret(cfg: SentinelSinkConfig) -> str:
    if cfg.client_secret:
        value = os.path.expandvars(cfg.client_secret)
        register_secret(value)
        return value
    if cfg.client_secret_file:
        value = PathRead(cfg.client_secret_file)
        register_secret(value)
        return value
    if cfg.client_secret_ref:
        name = cfg.client_secret_ref.split(":", 1)[-1]
        try:
            from prismor.runtime.cloaking.secrets_store import secrets_dir
            value = (secrets_dir() / name).read_text(encoding="utf-8").strip()
        except OSError as exc:
            raise AuthError("secret_ref", str(exc))
        register_secret(value)
        return value
    raise AuthError("missing_secret", "no client secret configured")


def PathRead(path: str) -> str:
    return open(path, "r", encoding="utf-8").read().strip()  # noqa: SIM115 — operator path


def _cert_assertion(cfg: SentinelSinkConfig, token_url: str, now: float) -> str:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
    from cryptography.x509 import load_pem_x509_certificate
    from cryptography import x509

    blob = open(cfg.certificate_file, "rb").read()  # noqa: SIM115
    password = os.path.expandvars(cfg.certificate_password).encode("utf-8") if cfg.certificate_password else None
    if password:
        register_secret(password.decode("utf-8", errors="ignore"))
    key = cert = None
    if blob.startswith(b"-----BEGIN"):
        try:
            key = serialization.load_pem_private_key(blob, password=password)
        except (ValueError, TypeError) as exc:
            raise SentinelConfigError(redact(f"certificate key: {exc.__class__.__name__}"))
        # The PEM may contain the cert after the key.
        marker = blob.find(b"-----BEGIN CERTIFICATE-----")
        if marker < 0:
            raise SentinelConfigError("certificate PEM has no certificate")
        cert = load_pem_x509_certificate(blob[marker:])
    else:
        try:
            from cryptography.hazmat.primitives.serialization.pkcs12 import load_key_and_certificates
            key, cert, _more = load_key_and_certificates(blob, password)
        except (ValueError, TypeError) as exc:
            raise SentinelConfigError(redact(f"certificate: {exc.__class__.__name__}"))
    if key is None or cert is None:
        raise SentinelConfigError("certificate could not be loaded")
    if isinstance(key, ec.EllipticCurvePrivateKey) or not isinstance(key, rsa.RSAPrivateKey):
        raise SentinelConfigError("RSA required")
    der = cert.public_bytes(serialization.Encoding.DER)
    now_i = int(now)
    claims = {
        "aud": token_url,
        "iss": cfg.client_id,
        "sub": cfg.client_id,
        "jti": str(uuid.uuid4()),
        "nbf": now_i,
        "iat": now_i,
        "exp": now_i + 600,
    }
    if cfg.legacy_rs256:
        # TODO(verify): whether any tenant still rejects PS256. Off unless opted in.
        header = {"alg": "RS256", "typ": "JWT", "x5t": _b64url(hashlib.sha1(der).digest())}  # nosec B324
        pad = padding.PKCS1v15()
        algo = hashes.SHA256()
    else:
        # TODO(verify): Entra's cert-credentials page says PSS. Salt length
        # DIGEST_LENGTH matches the PS256 JOSE profile; the page does not
        # spell the salt length out.
        header = {"alg": "PS256", "typ": "JWT", "x5t#S256": _b64url(hashlib.sha256(der).digest())}
        pad = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.DIGEST_LENGTH)
        algo = hashes.SHA256()
    if cfg.send_x5c:
        header["x5c"] = [_b64url(der)]
    signing = _b64url(json.dumps(header, separators=(",", ":")).encode()) + "." + _b64url(
        json.dumps(claims, separators=(",", ":")).encode()
    )
    signature = key.sign(signing.encode("ascii"), pad, algo)
    return signing + "." + _b64url(signature)


class TokenProvider:
    def __init__(self, cfg: SentinelSinkConfig, *, transport: Optional[Transport] = None,
                 clock=None) -> None:
        self.cfg = cfg
        self.transport = transport or _default_transport
        self.clock = clock or time.time

    def cache_key(self) -> tuple:
        return (self.cfg.auth_mode, self.cfg.token_authority, self.cfg.tenant_id,
                self.cfg.client_id, self.cfg.scope)

    def get_token(self, *, force: bool = False) -> str:
        now = float(self.clock())
        key = self.cache_key()
        if not force:
            cached = _CACHE.get(key, now)
            if cached:
                return cached
        if self.cfg.auth_mode == "client_secret":
            token, expires_in = self._client_secret(now)
        elif self.cfg.auth_mode == "client_certificate":
            token, expires_in = self._client_cert(now)
        elif self.cfg.auth_mode == "managed_identity":
            token, expires_in = self._managed(now)
        elif self.cfg.auth_mode == "workload_identity":
            token, expires_in = self._workload(now)
        else:
            raise AuthError("unsupported_auth", self.cfg.auth_mode)
        _CACHE.put(key, token, _refresh_at(now, expires_in))
        return token

    def invalidate(self) -> None:
        _CACHE.invalidate(self.cache_key())

    def _token_url(self) -> str:
        return f"{self.cfg.token_authority}/{self.cfg.tenant_id}/oauth2/v2.0/token"

    def _client_secret(self, now: float) -> Tuple[str, float]:
        secret = _load_secret(self.cfg)
        payload = _form_post(self.transport, self._token_url(), {
            "grant_type": "client_credentials",
            "client_id": self.cfg.client_id,
            "client_secret": secret,
            "scope": self.cfg.scope,
        }, self.cfg.timeout_seconds)
        return str(payload["access_token"]), _parse_expiry(payload, now)

    def _client_cert(self, now: float) -> Tuple[str, float]:
        assertion = _cert_assertion(self.cfg, self._token_url(), now)
        register_secret(assertion)
        payload = _form_post(self.transport, self._token_url(), {
            "grant_type": "client_credentials",
            "client_id": self.cfg.client_id,
            "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            "client_assertion": assertion,
            "scope": self.cfg.scope,
        }, self.cfg.timeout_seconds)
        return str(payload["access_token"]), _parse_expiry(payload, now)

    def _managed(self, now: float) -> Tuple[str, float]:
        identity_endpoint = os.environ.get("IDENTITY_ENDPOINT", "").strip()
        identity_header = os.environ.get("IDENTITY_HEADER", "")
        if identity_header:
            register_secret(identity_header)
        resource = self.cfg.resource
        client = self.cfg.managed_identity_client_id
        if identity_endpoint and identity_header:
            # TODO(verify): Container Apps api-version. App Service doc uses 2019-08-01;
            # the same header pair is used here until a Container Apps page says otherwise.
            url = identity_endpoint
            sep = "&" if "?" in url else "?"
            url = f"{url}{sep}resource={resource}&api-version=2019-08-01"
            if client:
                url += f"&client_id={client}"
            headers = {"X-IDENTITY-HEADER": identity_header, "Metadata": "true"}
        else:
            base = os.environ.get("PRISMOR_SENTINEL_IMDS_ENDPOINT", "http://169.254.169.254").rstrip("/")
            url = (
                f"{base}/metadata/identity/oauth2/token?api-version=2018-02-01&resource={resource}"
            )
            if client:
                url += f"&client_id={client}"
            headers = {"Metadata": "true"}
        status, _hdrs, body = self.transport("GET", url, headers, None, min(2.0, self.cfg.timeout_seconds))
        try:
            payload = json.loads(body.decode("utf-8") or "{}")
        except ValueError:
            payload = {}
        if status != 200 or not isinstance(payload, dict) or not payload.get("access_token"):
            raise AuthError(f"http_{status}", "managed identity token request failed")
        register_secret(str(payload["access_token"]))
        return str(payload["access_token"]), _parse_expiry(payload, now)

    def _workload(self, now: float) -> Tuple[str, float]:
        # The assertion file is re-read on every fetch. It is not cached.
        path = self.cfg.federated_token_file or os.environ.get("AZURE_FEDERATED_TOKEN_FILE", "")
        tenant = self.cfg.tenant_id or os.environ.get("AZURE_TENANT_ID", "")
        client = self.cfg.client_id or os.environ.get("AZURE_CLIENT_ID", "")
        if not path or not os.path.isfile(path):
            raise AuthError("auth_error", f"federated token file missing: {path}")
        assertion = open(path, "r", encoding="utf-8").read().strip()  # noqa: SIM115
        register_secret(assertion)
        authority = self.cfg.authority_host or os.environ.get("AZURE_AUTHORITY_HOST") or self.cfg.token_authority
        url = f"{authority.rstrip('/')}/{tenant}/oauth2/v2.0/token"
        payload = _form_post(self.transport, url, {
            "grant_type": "client_credentials",
            "client_id": client,
            "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            "client_assertion": assertion,
            "scope": self.cfg.scope,
        }, self.cfg.timeout_seconds)
        return str(payload["access_token"]), _parse_expiry(payload, now)


def clear_cache() -> None:
    _CACHE._items.clear()
