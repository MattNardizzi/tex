"""
Graph transport — the one read-only seam to the identity provider.

The IdP root is the seamless-discovery promise: one read-only admin-consent
grant, and Tex enumerates the estate itself instead of the client wiring up
Salesforce, Slack, and M365 one connector at a time. This module is that
seam, and only that seam — the HTTP plumbing to Microsoft Graph (Okta's
``/api/v1`` is the same shape), kept separate from the connector so the
connector logic is testable without a tenant.

Two implementations behind one Protocol:

  * ``LiveGraphTransport`` — real client-credentials auth, ``@odata.nextLink``
    pagination, ``429`` / ``Retry-After`` backoff, and delta links for the
    standing watch. This is what runs against a customer tenant.
  * ``FixtureGraphTransport`` — returns canned pages from an in-memory map,
    so the connector's graph-building and candidate-emission logic is unit-
    tested deterministically, exactly as the repo's other connectors are.

Credentials are never held here in source. ``LiveGraphTransport`` reads them
from the configuration object handed in at construction (which a deployment
populates from its secret store / environment). The grant is read-only:
the scopes a deployment consents to are ``Application.Read.All``,
``Directory.Read.All`` — enumeration only, never write.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any, Iterator, Protocol, runtime_checkable

DEFAULT_GRAPH_BASE = "https://graph.microsoft.com/v1.0"
DEFAULT_LOGIN_BASE = "https://login.microsoftonline.com"


@runtime_checkable
class GraphTransport(Protocol):
    """Reads pages of objects from an identity-provider directory API."""

    def get_paginated(self, path: str, params: dict[str, str] | None = None) -> Iterator[dict[str, Any]]:
        """Yield every object across all pages for a collection ``path``."""

    def get_delta(self, path: str, delta_link: str | None = None) -> tuple[list[dict[str, Any]], str | None]:
        """
        Yield the changed objects since ``delta_link`` (or a full first
        page) plus the next delta link to persist for the next sweep — the
        native standing-watch mechanism.
        """


@dataclass(frozen=True, slots=True)
class GraphCredentials:
    """Client-credentials config. Populated from the deployment's secret store."""

    tenant_id: str
    client_id: str
    client_secret: str
    graph_base: str = DEFAULT_GRAPH_BASE
    login_base: str = DEFAULT_LOGIN_BASE
    scope: str = "https://graph.microsoft.com/.default"


class LiveGraphTransport:
    """
    Live Microsoft Graph reader. Lazily imports ``httpx`` so the rest of the
    discovery layer (and its tests) never depend on it being installed.
    """

    def __init__(self, credentials: GraphCredentials, *, timeout: float = 30.0, max_retries: int = 5) -> None:
        self._creds = credentials
        self._timeout = timeout
        self._max_retries = max_retries
        self._token: str | None = None
        self._token_expiry: float = 0.0

    # ------------------------------------------------------------------ auth
    def _bearer(self) -> str:
        import httpx

        now = time.monotonic()
        if self._token is not None and now < self._token_expiry - 60:
            return self._token
        resp = httpx.post(
            f"{self._creds.login_base}/{self._creds.tenant_id}/oauth2/v2.0/token",
            data={
                "client_id": self._creds.client_id,
                "client_secret": self._creds.client_secret,
                "grant_type": "client_credentials",
                "scope": self._creds.scope,
            },
            timeout=self._timeout,
        )
        resp.raise_for_status()
        body = resp.json()
        self._token = body["access_token"]
        self._token_expiry = now + float(body.get("expires_in", 3600))
        return self._token

    def _get(self, url: str, params: dict[str, str] | None = None) -> dict[str, Any]:
        import httpx

        for attempt in range(self._max_retries):
            resp = httpx.get(
                url,
                params=params,
                headers={"Authorization": f"Bearer {self._bearer()}"},
                timeout=self._timeout,
            )
            if resp.status_code == 429:
                # Honour Retry-After; this is Graph's documented throttling
                # contract. Bounded by max_retries.
                wait = float(resp.headers.get("Retry-After", 2 ** attempt))
                time.sleep(min(wait, 60.0))
                continue
            resp.raise_for_status()
            return resp.json()
        raise RuntimeError("graph transport: exhausted retries against throttling")

    # ------------------------------------------------------------------ reads
    def get_paginated(self, path: str, params: dict[str, str] | None = None) -> Iterator[dict[str, Any]]:
        url = path if path.startswith("http") else f"{self._creds.graph_base}/{path.lstrip('/')}"
        next_params = params
        while url:
            body = self._get(url, next_params)
            for item in body.get("value", []):
                yield item
            url = body.get("@odata.nextLink", "")
            next_params = None  # nextLink already encodes the query

    def get_delta(self, path: str, delta_link: str | None = None) -> tuple[list[dict[str, Any]], str | None]:
        url = delta_link or (
            path if path.startswith("http") else f"{self._creds.graph_base}/{path.lstrip('/')}"
        )
        changed: list[dict[str, Any]] = []
        next_delta: str | None = None
        while url:
            body = self._get(url)
            changed.extend(body.get("value", []))
            if "@odata.nextLink" in body:
                url = body["@odata.nextLink"]
                continue
            next_delta = body.get("@odata.deltaLink")
            break
        return changed, next_delta


class FixtureGraphTransport:
    """
    Deterministic in-memory transport for tests. ``pages`` maps a collection
    path (e.g. ``"servicePrincipals"`` or
    ``"servicePrincipals/<id>/oauth2PermissionGrants"``) to the list of
    objects that path returns.
    """

    def __init__(self, pages: dict[str, list[dict[str, Any]]]) -> None:
        self._pages = {k.strip("/"): v for k, v in pages.items()}

    def get_paginated(self, path: str, params: dict[str, str] | None = None) -> Iterator[dict[str, Any]]:
        yield from self._pages.get(path.strip("/"), [])

    def get_delta(self, path: str, delta_link: str | None = None) -> tuple[list[dict[str, Any]], str | None]:
        # In tests, a delta with no prior link returns everything once; a
        # subsequent call with the link returns nothing new.
        if delta_link is not None:
            return [], delta_link
        items = list(self._pages.get(path.strip("/"), []))
        return items, f"delta::{path.strip('/')}"
