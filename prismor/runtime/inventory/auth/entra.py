"""Entra ID tokens for inventory collectors. Stdlib HTTP plus ``cryptography``.

Tokens stay in memory. An opt-in cache (``PRISMOR_INVENTORY_TOKEN_CACHE=1``)
writes the bearer to the Cloak secrets directory at mode 0600 and never prints
it. Device-code user instructions go to stderr; the access token does not.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import time
import uuid
from typing import Any, Dict, Optional
from urllib.parse import urlencode

from prismor.runtime.inventory.context import ScanContext

# Power Platform Admin Center, first-party app, from
# https://learn.microsoft.com/en-us/power-platform/admin/apps-to-allow
# Microsoft may refuse a public device-code grant against this client.
# A customer app registration is the supported alternative (--client-id).
PPAC_CLIENT_ID = "065d9450-1e87-434e-ac2f-69af271549ed"

_CACHE: Dict[str, str] = {}


class AuthError(Exception):
    """Authentication failed. ``code`` is a short reason; the message has no token."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def _form(ctx: ScanContext, url: str, fields: Dict[str, str]) -> Dict[str, Any]:
    body = urlencode(fields).encode("utf-8")
    result = ctx.http(
        "POST", url,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        body=body, timeout=ctx.request_timeout,
    )
    if result.status != 200:
        raise AuthError(f"http_{result.status}")
    try:
        payload = result.json()
    except (ValueError, UnicodeError):
        raise AuthError("bad_token_response")
    if not isinstance(payload, dict):
        raise AuthError("bad_token_response")
    return payload


def _remember(token: str, cache_key: str) -> str:
    _CACHE[cache_key] = token
    if os.environ.get("PRISMOR_INVENTORY_TOKEN_CACHE") == "1":
        _write_cloak(token)
    return token


def _write_cloak(token: str) -> None:
    """Store a bearer in the secrets directory. The value is not logged."""
    root = os.environ.get("PRISMOR_SECRETS_DIR", "").strip()
    if not root:
        home = os.path.expanduser("~/.prismor/secrets")
        root = home
    directory = os.path.abspath(root)
    os.makedirs(directory, mode=0o700, exist_ok=True)
    try:
        os.chmod(directory, 0o700)
    except OSError:
        pass
    path = os.path.join(directory, "inventory_access_token")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, token.encode("utf-8"))
    finally:
        os.close(fd)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _cert_assertion(tenant: str, client_id: str, cert_path: str) -> str:
    """RS256 client assertion. The PEM holds the certificate and the private key."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding

    blob = open(cert_path, "rb").read()  # noqa: SIM115 — path is operator-supplied
    key = serialization.load_pem_private_key(blob, password=None)
    cert = x509.load_pem_x509_certificate(blob)
    der = cert.public_bytes(serialization.Encoding.DER)
    try:
        thumb = hashlib.sha1(der, usedforsecurity=False).digest()  # nosec B324
    except TypeError:  # Python 3.8 has no usedforsecurity
        thumb = hashlib.sha1(der).digest()  # nosec B324
    header = {"alg": "RS256", "typ": "JWT", "x5t": _b64url(thumb)}
    now = int(time.time())
    payload = {
        "aud": f"https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token",
        "iss": client_id,
        "sub": client_id,
        "jti": str(uuid.uuid4()),
        "nbf": now,
        "exp": now + 600,
    }
    signing = (
        _b64url(json.dumps(header, separators=(",", ":")).encode())
        + "."
        + _b64url(json.dumps(payload, separators=(",", ":")).encode())
    )
    signature = key.sign(signing.encode("ascii"), padding.PKCS1v15(), hashes.SHA256())
    return signing + "." + _b64url(signature)


def _client_credentials(ctx: ScanContext, tenant: str, client_id: str, scope: str,
                        secret: str = "", assertion: str = "") -> str:
    fields = {
        "client_id": client_id,
        "scope": scope,
        "grant_type": "client_credentials",
    }
    if assertion:
        fields["client_assertion_type"] = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
        fields["client_assertion"] = assertion
    else:
        fields["client_secret"] = secret
    url = f"https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token"
    payload = _form(ctx, url, fields)
    token = str(payload.get("access_token") or "")
    if not token:
        raise AuthError("no_access_token")
    return token


def _device_code(ctx: ScanContext, tenant: str, client_id: str, scope: str) -> str:
    import sys
    url = f"https://login.microsoftonline.com/{tenant}/oauth2/v2.0/devicecode"
    started = _form(ctx, url, {"client_id": client_id, "scope": scope})
    message = str(started.get("message") or "")
    if message:
        sys.stderr.write(message.rstrip() + "\n")
    else:
        sys.stderr.write(
            f"Open {started.get('verification_uri') or ''} and enter {started.get('user_code') or ''}\n"
        )
    device = str(started.get("device_code") or "")
    if not device:
        raise AuthError("no_device_code")
    interval = max(1, int(started.get("interval") or 5))
    token_url = f"https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token"
    deadline = time.time() + int(started.get("expires_in") or 900)
    while time.time() < deadline:
        time.sleep(interval)
        result = ctx.http(
            "POST", token_url,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            body=urlencode({
                "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                "client_id": client_id,
                "device_code": device,
            }).encode("utf-8"),
            timeout=ctx.request_timeout,
        )
        try:
            payload = result.json() if result.body else {}
        except ValueError:
            payload = {}
        if not isinstance(payload, dict):
            payload = {}
        if result.status == 200 and payload.get("access_token"):
            return str(payload["access_token"])
        error = str(payload.get("error") or "")
        if error == "authorization_pending":
            continue
        if error == "slow_down":
            interval += 5
            continue
        raise AuthError(error or f"http_{result.status}")
    raise AuthError("device_code_expired")


def _managed_identity(ctx: ScanContext, scope: str) -> str:
    identity_endpoint = os.environ.get("IDENTITY_ENDPOINT", "").strip()
    if identity_endpoint:
        url = identity_endpoint
        separator = "&" if "?" in url else "?"
        resource = scope.replace("/.default", "")
        url = f"{url}{separator}api-version=2019-08-01&resource={resource}"
        headers = {"X-IDENTITY-HEADER": os.environ.get("IDENTITY_HEADER", ""), "Metadata": "true"}
    else:
        resource = scope.replace("/.default", "")
        url = (
            "http://169.254.169.254/metadata/identity/oauth2/token"
            f"?api-version=2018-02-01&resource={resource}"
        )
        headers = {"Metadata": "true"}
    result = ctx.http("GET", url, headers=headers, timeout=ctx.request_timeout)
    if result.status != 200:
        raise AuthError(f"http_{result.status}")
    try:
        payload = result.json()
    except ValueError:
        raise AuthError("bad_token_response")
    token = str((payload or {}).get("access_token") or "")
    if not token:
        raise AuthError("no_access_token")
    return token


def access_token(ctx: ScanContext, scope: str) -> str:
    """A bearer for ``scope``. Reads secrets from the environment, never from argv."""
    auth = dict(ctx.auth or {})
    mode = str(auth.get("mode") or "env").lower()
    if ctx.fixture_http or mode == "fixture":
        return "fixture"
    token_env = str(auth.get("token_env") or "")
    if mode == "env" or token_env:
        if token_env:
            token = os.environ.get(token_env, "").strip()
            if not token:
                raise AuthError("missing_token_env")
            return token
        if mode == "env":
            raise AuthError("missing_token_env")
    tenant = str(auth.get("tenant") or "organizations")
    client_id = str(auth.get("client_id") or PPAC_CLIENT_ID)
    cache_key = "|".join([mode, tenant, client_id, scope])
    cached = _CACHE.get(cache_key)
    if cached:
        return cached
    if mode == "managed-identity":
        return _remember(_managed_identity(ctx, scope), cache_key)
    if mode == "client-credentials":
        cert = str(auth.get("cert") or "")
        if cert:
            assertion = _cert_assertion(tenant, client_id, cert)
            return _remember(_client_credentials(ctx, tenant, client_id, scope, assertion=assertion), cache_key)
        secret_env = str(auth.get("secret_env") or "")
        secret = os.environ.get(secret_env, "").strip() if secret_env else ""
        if not secret:
            raise AuthError("missing_secret_env")
        return _remember(_client_credentials(ctx, tenant, client_id, scope, secret=secret), cache_key)
    if mode == "device-code":
        return _remember(_device_code(ctx, tenant, client_id, scope), cache_key)
    raise AuthError("unsupported_auth")


def clear_cache() -> None:
    _CACHE.clear()
