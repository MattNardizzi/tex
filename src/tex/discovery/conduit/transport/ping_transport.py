"""
Ping transport — PingFederate / PingOne behind the unchanged GraphTransport.

Ping deployments vary (self-hosted PingFederate OAuth Client Management REST vs
PingOne AIC), so the ``base_url`` is **pluggable** per deployment. Pagination is
PingOne's HAL ``_links.next.href`` cursor (PingFederate returns a flat list,
handled as a single page). Auth is an injected bearer ``token_provider``.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any, Iterator


class PingTransport:
    def __init__(
        self,
        *,
        base_url: str,
        token_provider: Callable[[], str],
        items_key: str = "_embedded.clients",
        timeout: float = 30.0,
    ) -> None:
        self._base = base_url.rstrip("/")
        self._token_provider = token_provider
        self._items_key = items_key
        self._timeout = timeout

    def _url(self, path: str) -> str:
        return path if path.startswith("http") else f"{self._base}/{path.lstrip('/')}"

    @staticmethod
    def _dig(body: dict[str, Any], dotted: str) -> list[dict[str, Any]]:
        node: Any = body
        for part in dotted.split("."):
            if not isinstance(node, dict):
                return []
            node = node.get(part)
        if isinstance(node, list):
            return node
        # PingFederate returns a bare list under "items" or the top level.
        return body.get("items") if isinstance(body.get("items"), list) else []

    def get_paginated(self, path: str, params: dict[str, str] | None = None) -> Iterator[dict[str, Any]]:
        import httpx

        url = self._url(path)
        while url:
            resp = httpx.get(
                url,
                params=params,
                headers={"Authorization": f"Bearer {self._token_provider()}"},
                timeout=self._timeout,
            )
            resp.raise_for_status()
            body = resp.json()
            items = body if isinstance(body, list) else self._dig(body, self._items_key)
            for item in items:
                yield item
            # PingOne HAL cursor.
            nxt = (body.get("_links", {}) or {}).get("next", {}) if isinstance(body, dict) else {}
            url = nxt.get("href") if isinstance(nxt, dict) else None
            params = None

    def get_delta(self, path: str, delta_link: str | None = None) -> tuple[list[dict[str, Any]], str | None]:
        items = list(self.get_paginated(delta_link or path))
        return items, delta_link
