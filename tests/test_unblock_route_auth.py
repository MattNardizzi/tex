"""
Wave-0 credibility floor — auth on the four formerly-open route groups.

Before this change, ``/v1/vet/*``, ``/v1/zkprov/*``, ``/v1/tee/*`` and
``/v1/ecosystem/twin/simulate`` carried NO authentication dependency.
With ``TEX_API_KEYS`` configured the rest of the API enforced keys, but
these four surfaces were reachable by anyone on the wire — including the
identity-document **revocation** endpoint ``POST /v1/vet/update-aid-status``,
which let an unauthenticated caller revoke or suspend any agent's AID.

What these tests pin (each would FAIL if the auth dependency were removed):

* With keys configured, an **unauthenticated** request to any of the four
  surfaces returns ``401``.
* Read/verify surfaces require ``evidence:read``; mutating / credential-minting
  surfaces additionally require ``evidence:write``. A read-only key gets ``403``
  on a write endpoint (revocation, issue, issue-commitment).
* A correctly-scoped key passes the gate.
* The keyless **dev** posture (no ``TEX_API_KEYS``) is preserved: the anonymous
  principal carries every scope, so local workflows keep working — this is the
  property that lets us close the surface without breaking dev.

Auth state is read per-request (``authenticate_request`` re-parses the env on
every call), so a single app can be exercised under both postures by toggling
``TEX_API_KEYS`` via ``monkeypatch``.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

# A reader key carries only ``evidence:read``; a writer key carries both
# ``evidence:read`` and ``evidence:write``. Format is
# ``<key>:<tenant>:<scope+scope>`` (the auth parser splits on ":" max 3 ways,
# so the ":" inside a scope name survives).
_KEYS = "key_reader:default:evidence:read,key_writer:default:evidence:read+evidence:write"
_READER = {"Authorization": "Bearer key_reader"}
_WRITER = {"Authorization": "Bearer key_writer"}

_TWIN_BODY = {
    "fork_timestamp_iso": "2026-05-24T12:00:00+00:00",
    "perturbation": {"compromise_delta": 0.3, "drift_delta": 0.2, "label": "auth_test"},
    "steps": 4,
}

_ISSUE_AID_BODY = {
    "agent_id": "auth-test-agent",
    "issuer_did": "did:tex:issuer:t",
    "model_measurement": "sha256:m",
    "software_stack_measurement": "sha256:s",
    "algorithm": "ed25519",
}


@pytest.fixture
def keyed_client(monkeypatch) -> TestClient:
    """App with ``TEX_API_KEYS`` configured → the production auth posture."""
    monkeypatch.setenv("TEX_API_KEYS", _KEYS)
    # CORS reads env at build time; nothing here depends on it.
    monkeypatch.delenv("TEX_CORS_ALLOW_ORIGINS", raising=False)
    from tex.main import create_app

    return TestClient(create_app())


@pytest.fixture
def keyless_client(monkeypatch) -> TestClient:
    """App with no API keys → the keyless dev posture (anonymous = all scopes)."""
    monkeypatch.delenv("TEX_API_KEYS", raising=False)
    from tex.main import create_app

    return TestClient(create_app())


# --------------------------------------------------------------------------- #
# THE PRIORITY: identity-document revocation must not be reachable unauth'd.   #
# --------------------------------------------------------------------------- #


class TestAidRevocationRequiresAuth:
    _PATH = "/v1/vet/update-aid-status"
    _BODY = {"agent_id": "victim-agent", "new_status": "revoked"}

    def test_unauthenticated_revocation_is_401(self, keyed_client: TestClient) -> None:
        r = keyed_client.post(self._PATH, json=self._BODY)
        assert r.status_code == 401, r.text

    def test_read_only_key_cannot_revoke_403(self, keyed_client: TestClient) -> None:
        r = keyed_client.post(self._PATH, headers=_READER, json=self._BODY)
        assert r.status_code == 403, r.text

    def test_write_scoped_key_can_revoke(self, keyed_client: TestClient) -> None:
        # Issue an AID first (also a write endpoint) so revocation actually
        # flips a real record, proving the request reached the handler.
        issued = keyed_client.post(
            "/v1/vet/issue-aid", headers=_WRITER, json=_ISSUE_AID_BODY
        )
        assert issued.status_code == 200, issued.text
        r = keyed_client.post(
            self._PATH,
            headers=_WRITER,
            json={"agent_id": "auth-test-agent", "new_status": "revoked"},
        )
        assert r.status_code == 200, r.text
        assert r.json()["updated"] is True

    def test_keyless_dev_revocation_still_open(self, keyless_client: TestClient) -> None:
        # No keys configured → anonymous principal → dev workflow unbroken.
        r = keyless_client.post(self._PATH, json=self._BODY)
        assert r.status_code == 200, r.text


# --------------------------------------------------------------------------- #
# /v1/vet/* — read vs write scope                                             #
# --------------------------------------------------------------------------- #


class TestVetAuth:
    def test_issue_aid_unauthenticated_is_401(self, keyed_client: TestClient) -> None:
        assert keyed_client.post("/v1/vet/issue-aid", json=_ISSUE_AID_BODY).status_code == 401

    def test_issue_aid_read_only_is_403(self, keyed_client: TestClient) -> None:
        r = keyed_client.post("/v1/vet/issue-aid", headers=_READER, json=_ISSUE_AID_BODY)
        assert r.status_code == 403, r.text

    def test_get_aid_read_scope_passes_gate(self, keyed_client: TestClient) -> None:
        # GET is a read surface: a reader key passes auth. Unknown id → 404,
        # which is a post-auth business result (NOT 401/403).
        r = keyed_client.get("/v1/vet/aid/nobody", headers=_READER)
        assert r.status_code == 404, r.text

    def test_get_aid_unauthenticated_is_401(self, keyed_client: TestClient) -> None:
        assert keyed_client.get("/v1/vet/aid/nobody").status_code == 401


# --------------------------------------------------------------------------- #
# /v1/tee/* — read-only verification surface                                  #
# --------------------------------------------------------------------------- #


class TestTeeAuth:
    def test_status_unauthenticated_is_401(self, keyed_client: TestClient) -> None:
        assert keyed_client.get("/v1/tee/status").status_code == 401

    def test_status_read_scope_ok(self, keyed_client: TestClient) -> None:
        r = keyed_client.get("/v1/tee/status", headers=_READER)
        assert r.status_code == 200, r.text

    def test_keyless_dev_status_open(self, keyless_client: TestClient) -> None:
        assert keyless_client.get("/v1/tee/status").status_code == 200


# --------------------------------------------------------------------------- #
# /v1/zkprov/* — read vs write scope                                          #
# --------------------------------------------------------------------------- #


class TestZkprovAuth:
    def test_health_unauthenticated_is_401(self, keyed_client: TestClient) -> None:
        assert keyed_client.get("/v1/zkprov/health").status_code == 401

    def test_health_read_scope_ok(self, keyed_client: TestClient) -> None:
        assert keyed_client.get("/v1/zkprov/health", headers=_READER).status_code == 200

    def test_issue_commitment_read_only_is_403(self, keyed_client: TestClient) -> None:
        # Write endpoint: read-only key is rejected with 403 before any
        # request-body validation (which would otherwise 400).
        r = keyed_client.post("/v1/zkprov/issue-commitment", headers=_READER, json={})
        assert r.status_code == 403, r.text

    def test_issue_commitment_write_scope_passes_gate(self, keyed_client: TestClient) -> None:
        # Writer passes auth; the empty body then fails schema validation (422),
        # which proves the request crossed the auth gate (NOT 401/403).
        r = keyed_client.post("/v1/zkprov/issue-commitment", headers=_WRITER, json={})
        assert r.status_code not in (401, 403), r.text


# --------------------------------------------------------------------------- #
# /v1/ecosystem/twin/simulate — read surface                                  #
# --------------------------------------------------------------------------- #


class TestEcosystemTwinAuth:
    _PATH = "/v1/ecosystem/twin/simulate"

    def test_simulate_unauthenticated_is_401(self, keyed_client: TestClient) -> None:
        assert keyed_client.post(self._PATH, json=_TWIN_BODY).status_code == 401

    def test_simulate_read_scope_passes_gate(self, keyed_client: TestClient) -> None:
        # The twin is wired by create_app(); a reader key should get a 200
        # trajectory, NOT an auth rejection.
        r = keyed_client.post(self._PATH, headers=_READER, json=_TWIN_BODY)
        assert r.status_code == 200, r.text

    def test_keyless_dev_simulate_open(self, keyless_client: TestClient) -> None:
        assert keyless_client.post(self._PATH, json=_TWIN_BODY).status_code == 200
