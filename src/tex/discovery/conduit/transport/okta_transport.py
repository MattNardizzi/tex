"""
Okta transport — Okta ``/api/v1`` behind the unchanged ``GraphTransport``
Protocol.

``graph_transport.py`` already abstracts ``get_paginated`` + ``get_delta`` and
its docstring already says "Okta ``/api/v1`` is the same shape." It is — only
the mechanics differ:

  * **Pagination** is the ``Link`` header with ``rel="next"`` (not
    ``@odata.nextLink``), and Okta collection endpoints return a bare JSON array
    (not ``{"value": [...]}``).
  * **Auth** is OAuth 2.0 client-credentials with a **private-key JWT client
    assertion** — a rotatable service app, never a static SSWS token.
  * **Delta / standing watch** is System Log polling (``/api/v1/logs?since=…``),
    advancing on the ``Link rel="next"`` cursor.

The connector logic on top is identical to Entra's — it is the same
``ProviderConsentGraphConnector``, driven by ``OKTA_PROFILE``. This transport is
fixture-free in tests: the Okta profile is exercised with
``FixtureGraphTransport`` fed raw Okta-shaped rows, exactly as Entra is. This
live transport is the production path.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from typing import Any, Iterator

DEFAULT_API_BASE = "/api/v1"


def build_client_assertion_jwt(
    *,
    client_id: str,
    token_endpoint: str,
    private_key_pem: bytes,
    key_id: str | None = None,
    now: int,
    ttl_seconds: int = 300,
    jti: str,
) -> str:
    """Build a signed RS256 private-key-JWT client assertion for Okta's
    client-credentials flow (OAuth 2.1, least-privilege, rotatable — NOT SSWS).

    Deterministic given ``now``/``jti`` so it stays free of ``random``/clock
    surprises; the caller mints those. Uses ``cryptography`` directly (no PyJWT
    dependency)."""
    import base64
    import json

    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.hazmat.primitives.serialization import load_pem_private_key

    def _b64url(raw: bytes) -> str:
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")

    header: dict[str, Any] = {"alg": "RS256", "typ": "JWT"}
    if key_id:
        header["kid"] = key_id
    claims = {
        "iss": client_id,
        "sub": client_id,
        "aud": token_endpoint,
        "iat": now,
        "exp": now + ttl_seconds,
        "jti": jti,
    }
    signing_input = (
        _b64url(json.dumps(header, separators=(",", ":")).encode("utf-8"))
        + "."
        + _b64url(json.dumps(claims, separators=(",", ":")).encode("utf-8"))
    ).encode("ascii")
    key = load_pem_private_key(private_key_pem, password=None)
    signature = key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
    return signing_input.decode("ascii") + "." + _b64url(signature)


class OktaTransport:
    """
    Live Okta ``/api/v1`` reader behind the ``GraphTransport`` Protocol.

    Construct with ``org_url`` and a ``token_provider`` callable that returns a
    bearer token. Use :meth:`with_private_key_jwt` for the standard service-app
    auth. ``httpx`` is imported lazily so the discovery layer (and its tests)
    never depend on it being installed.
    """

    def __init__(
        self,
        *,
        org_url: str,
        token_provider: Callable[[], str],
        api_base: str = DEFAULT_API_BASE,
        timeout: float = 30.0,
        max_retries: int = 5,
        page_limit: int = 200,
    ) -> None:
        self._org_url = org_url.rstrip("/")
        self._token_provider = token_provider
        self._api_base = api_base
        self._timeout = timeout
        self._max_retries = max_retries
        self._page_limit = page_limit

    # ------------------------------------------------------------------ auth
    @classmethod
    def with_private_key_jwt(
        cls,
        *,
        org_url: str,
        client_id: str,
        private_key_pem: bytes,
        scopes: tuple[str, ...],
        key_id: str | None = None,
        nonce_source: Callable[[], tuple[int, str]] | None = None,
        **kwargs: Any,
    ) -> "OktaTransport":
        """Build a transport whose token provider performs client-credentials +
        private-key-JWT against ``{org_url}/oauth2/v1/token``.

        ``nonce_source`` returns ``(now_epoch, jti)`` per token mint; a
        deployment supplies a real clock + unique jti. Tokens are cached until
        ~60s before expiry."""
        org = org_url.rstrip("/")
        token_endpoint = f"{org}/oauth2/v1/token"
        scope_str = " ".join(scopes)
        cache: dict[str, Any] = {"token": None, "expiry": 0.0}

        def _default_nonce() -> tuple[int, str]:
            now = int(time.time())
            return now, f"{client_id}-{now}"

        nonce = nonce_source or _default_nonce

        def _provider() -> str:
            import httpx

            mono = time.monotonic()
            if cache["token"] is not None and mono < cache["expiry"] - 60:
                return cache["token"]
            now, jti = nonce()
            assertion = build_client_assertion_jwt(
                client_id=client_id,
                token_endpoint=token_endpoint,
                private_key_pem=private_key_pem,
                key_id=key_id,
                now=now,
                jti=jti,
            )
            resp = httpx.post(
                token_endpoint,
                data={
                    "grant_type": "client_credentials",
                    "scope": scope_str,
                    "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                    "client_assertion": assertion,
                },
                timeout=kwargs.get("timeout", 30.0),
            )
            resp.raise_for_status()
            body = resp.json()
            cache["token"] = body["access_token"]
            cache["expiry"] = mono + float(body.get("expires_in", 3600))
            return cache["token"]

        return cls(org_url=org_url, token_provider=_provider, **kwargs)

    # ------------------------------------------------------------------ http
    def _url(self, path: str) -> str:
        if path.startswith("http"):
            return path
        return f"{self._org_url}{self._api_base}/{path.lstrip('/')}"

    def _get(self, url: str, params: dict[str, str] | None):
        import httpx

        for attempt in range(self._max_retries):
            resp = httpx.get(
                url,
                params=params,
                headers={
                    "Authorization": f"Bearer {self._token_provider()}",
                    "Accept": "application/json",
                },
                timeout=self._timeout,
            )
            if resp.status_code == 429:
                wait = float(resp.headers.get("Retry-After", 2 ** attempt))
                time.sleep(min(wait, 60.0))
                continue
            resp.raise_for_status()
            return resp
        raise RuntimeError("okta transport: exhausted retries against throttling")

    @staticmethod
    def _next_link(resp: Any) -> str | None:
        """Okta paginates via RFC 5988 ``Link`` headers; follow ``rel="next"``."""
        link = resp.headers.get("link") or resp.headers.get("Link")
        if not link:
            return None
        for part in link.split(","):
            section = part.split(";")
            if len(section) < 2:
                continue
            url = section[0].strip().strip("<>")
            if any('rel="next"' in s.strip() or "rel=next" in s.strip() for s in section[1:]):
                return url
        return None

    # ------------------------------------------------------------------ reads
    def get_paginated(self, path: str, params: dict[str, str] | None = None) -> Iterator[dict[str, Any]]:
        url = self._url(path)
        next_params = dict(params or {})
        next_params.setdefault("limit", str(self._page_limit))
        while url:
            resp = self._get(url, next_params)
            body = resp.json()
            # Okta collections return a bare array; some return {"value": [...]}.
            items = body if isinstance(body, list) else body.get("value", [])
            for item in items:
                yield item
            url = self._next_link(resp)
            next_params = None  # the next link already encodes the cursor

    def get_delta(self, path: str, delta_link: str | None = None) -> tuple[list[dict[str, Any]], str | None]:
        """Standing watch via System Log polling. ``delta_link`` is the Okta
        ``Link rel="next"`` cursor persisted from the prior sweep; on first call
        it polls from now-ish and returns the advancing cursor."""
        url = delta_link or self._url(path)
        changed: list[dict[str, Any]] = []
        resp = self._get(url, None if delta_link else {"limit": str(self._page_limit)})
        body = resp.json()
        changed.extend(body if isinstance(body, list) else body.get("value", []))
        return changed, self._next_link(resp) or delta_link
