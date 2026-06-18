"""
Google transports — Workspace + GCP, behind the unchanged GraphTransport.

Google is honestly **two grants**, never one OAuth click:

  * ``GoogleWorkspaceTransport`` reads the Admin SDK (Directory + Reports
    token-audit) under domain-wide delegation — the Workspace half.
  * ``GoogleIamAssetTransport`` reads Cloud Asset Inventory
    (``cloudasset.googleapis.com``) for org-wide service accounts and their IAM
    role bindings — the GCP half.

Both paginate with ``pageToken`` and return ``{"<collection>": [...],
"nextPageToken": "..."}``. Auth is an injected bearer ``token_provider`` (a
deployment wires service-account / DWD token minting; tests use fixtures via
``FixtureGraphTransport``). ``httpx`` is imported lazily.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any, Iterator

_GW_BASE = "https://admin.googleapis.com"
_ASSET_BASE = "https://cloudasset.googleapis.com/v1"


class _PageTokenTransport:
    """Shared pageToken pagination for Google JSON APIs."""

    def __init__(
        self,
        *,
        base_url: str,
        token_provider: Callable[[], str],
        items_key: str,
        timeout: float = 30.0,
    ) -> None:
        self._base = base_url.rstrip("/")
        self._token_provider = token_provider
        self._items_key = items_key
        self._timeout = timeout

    def _url(self, path: str) -> str:
        return path if path.startswith("http") else f"{self._base}/{path.lstrip('/')}"

    def get_paginated(self, path: str, params: dict[str, str] | None = None) -> Iterator[dict[str, Any]]:
        import httpx

        url = self._url(path)
        page_params = dict(params or {})
        while True:
            resp = httpx.get(
                url,
                params=page_params,
                headers={"Authorization": f"Bearer {self._token_provider()}"},
                timeout=self._timeout,
            )
            resp.raise_for_status()
            body = resp.json()
            items = body.get(self._items_key) or body.get("value") or []
            for item in items:
                yield item
            token = body.get("nextPageToken")
            if not token:
                break
            page_params["pageToken"] = token

    def get_delta(self, path: str, delta_link: str | None = None) -> tuple[list[dict[str, Any]], str | None]:
        # Google's "delta" is a time-windowed Reports/audit query; the daily job
        # supplies the window. With no cursor we read one page and return the
        # nextPageToken as the advancing cursor.
        import httpx

        url = self._url(path)
        params = {"pageToken": delta_link} if delta_link else {}
        resp = httpx.get(
            url,
            params=params,
            headers={"Authorization": f"Bearer {self._token_provider()}"},
            timeout=self._timeout,
        )
        resp.raise_for_status()
        body = resp.json()
        items = body.get(self._items_key) or body.get("value") or []
        return list(items), body.get("nextPageToken") or delta_link


class GoogleWorkspaceTransport(_PageTokenTransport):
    """Admin SDK Directory + Reports (token-audit) reader (DWD)."""

    def __init__(self, *, token_provider: Callable[[], str], **kwargs: Any) -> None:
        super().__init__(
            base_url=_GW_BASE, token_provider=token_provider, items_key="items", **kwargs
        )


class GoogleIamAssetTransport(_PageTokenTransport):
    """Cloud Asset Inventory reader for org-wide service accounts + IAM bindings."""

    def __init__(self, *, token_provider: Callable[[], str], **kwargs: Any) -> None:
        super().__init__(
            base_url=_ASSET_BASE, token_provider=token_provider, items_key="assets", **kwargs
        )
