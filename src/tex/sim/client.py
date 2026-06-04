"""
client.py — the simulator's wire to a running Tex backend.

Stdlib only (urllib), so the simulator adds no dependency to the repo. Every
call hits a REAL endpoint on a running `uvicorn tex.main:app`:

    POST /evaluate                          -> one action through the PDP (audit path)
    POST /v1/govern/decide                  -> one action through the live PEP (surfaces holds)
    GET  /v1/agents                         -> the discovered inventory
    GET  /v1/agents/{id}                    -> one agent
    GET  /v1/agents/{id}/ledger             -> that agent's sealed records
    GET  /decisions/{id}/evidence-bundle    -> the hash-chained proof
    GET  /v1/vigil                          -> what Tex chose to say
    POST /v1/vigil/explain                  -> finish the story over anchors
    GET  /v1/surface/discovery/status       -> has ignition fired?
    POST /v1/surface/discovery/ignite       -> begin watching (maps the estate)
    GET  /v1/system/state                   -> chain-integrity snapshot

Against a keyless (dev) backend no auth header is needed. Against a keyed
backend, pass api_key; it is sent as `Authorization: Bearer`.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any


class TexClientError(RuntimeError):
    def __init__(self, status: int, path: str, body: str):
        super().__init__(f"Tex API {status} on {path}: {body[:300]}")
        self.status = status
        self.path = path
        self.body = body


@dataclass
class TexClient:
    base_url: str = "http://localhost:8000"
    api_key: str | None = None
    timeout: float = 30.0

    def _request(self, method: str, path: str, payload: dict | None = None) -> Any:
        url = f"{self.base_url.rstrip('/')}{path}"
        data = json.dumps(payload).encode() if payload is not None else None
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                raw = resp.read().decode()
                return json.loads(raw) if raw else None
        except urllib.error.HTTPError as e:
            body = e.read().decode(errors="replace")
            raise TexClientError(e.code, path, body) from e
        except urllib.error.URLError as e:
            raise TexClientError(0, path, str(e.reason)) from e

    # -- decision path ---------------------------------------------------- #
    def evaluate(self, payload: dict) -> dict:
        return self._request("POST", "/evaluate", payload)

    def decide(self, payload: dict) -> dict:
        """The live enforcement path every PEP calls. Unlike /evaluate (the
        audit surface), an ABSTAIN here is pushed to the held sink and rises on
        the vigil — this is the path that makes holds reach the glass."""
        return self._request("POST", "/v1/govern/decide", payload)

    def evidence_bundle(self, decision_id: str) -> dict:
        return self._request("GET", f"/decisions/{decision_id}/evidence-bundle")

    def replay(self, decision_id: str) -> dict:
        return self._request("GET", f"/decisions/{decision_id}/replay")

    # -- inventory / client question loop --------------------------------- #
    def list_agents(self, params: str = "") -> Any:
        return self._request("GET", f"/v1/agents{params}")

    def get_agent(self, agent_id: str) -> dict:
        return self._request("GET", f"/v1/agents/{agent_id}")

    def update_agent(self, agent_id: str, patch: dict) -> dict:
        """PATCH an agent (e.g. promote trust_tier) — the operator path used
        by live mode to onboard the governed cohort."""
        return self._request("PATCH", f"/v1/agents/{agent_id}", patch)

    def agent_ledger(self, agent_id: str) -> Any:
        return self._request("GET", f"/v1/agents/{agent_id}/ledger")

    # -- voice ------------------------------------------------------------ #
    def vigil(self) -> dict:
        return self._request("GET", "/v1/vigil")

    def vigil_explain(self, dimension: str, claim_text: str | None = None) -> dict:
        return self._request("POST", "/v1/vigil/explain",
                             {"dimension": dimension, "claim_text": claim_text, "tenant_id": None})

    # -- discovery surface ------------------------------------------------ #
    def discovery_status(self, tenant_id: str | None = None) -> dict:
        q = f"?tenant_id={tenant_id}" if tenant_id else ""
        return self._request("GET", f"/v1/surface/discovery/status{q}")

    def ignite(self, tenant_id: str | None = None) -> dict:
        q = f"?tenant_id={tenant_id}" if tenant_id else ""
        return self._request("POST", f"/v1/surface/discovery/ignite{q}")

    def system_state(self) -> dict:
        return self._request("GET", "/v1/system/state")

    def health(self) -> Any:
        return self._request("GET", "/health")
