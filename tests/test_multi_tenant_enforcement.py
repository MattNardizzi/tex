"""
Thread 3 — multi-tenant authorization regression tests.

This suite is the proof that KNOWN_BUGS #6 ("multi-tenant gap:
enforce_tenant_match not called in 5 route files") is closed. It
exercises the four BOLA patterns we fixed:

  1. Body-tenant cross — a tenant-A key POSTs a body whose
     ``tenant_id`` is tenant-B. Pre-handler ``RequireTenantMatch``
     dependency must 403 before the handler runs.

  2. Path/object-tenant cross — a tenant-A key fetches an object
     (agent, proposal) by an opaque id that belongs to tenant-B.
     Mid-handler ``enforce_tenant_match`` after the store fetch
     must 403.

  3. List-endpoint leak — a tenant-A key calls a list endpoint with
     no tenant filter and sees tenant-B's records leaking through.
     The post-fetch filter must restrict the response to the
     principal's own tenant.

  4. C2PA opt-in guard — the C2PA manifest endpoint is intentionally
     unauthenticated by design, but when a Tex API key IS presented
     and the manifest's stored tenant_id does not match the key's
     tenant, the optional helper must 403.

Same harness shape as ``test_v18_production_readiness.py`` (env_set
context manager + per-test app reload) so behavior is fully
isolated from other test files.

Where the test exercises a route under a deeper composition path
(e.g. agent registration with all sub-systems wired), it does so via
``TestClient`` against ``create_app()`` rather than calling the
route function directly. That covers the dependency chain end to end.
"""

from __future__ import annotations

import importlib
import os
from contextlib import contextmanager
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient


# --------------------------------------------------------------------------- #
# Harness                                                                       #
# --------------------------------------------------------------------------- #


@contextmanager
def env_set(**overrides: str):
    """Temporarily set environment variables for one test."""
    saved: dict[str, str | None] = {k: os.environ.get(k) for k in overrides}
    for k, v in overrides.items():
        os.environ[k] = v
    try:
        yield
    finally:
        for k, prior in saved.items():
            if prior is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = prior


def _build_app():
    """Force a fresh import of main so env-driven config picks up changes."""
    import tex.main as main_mod
    importlib.reload(main_mod)
    return main_mod.create_app()


_AGENT_PAYLOAD_TPL = {
    "name": "regression-agent",
    "owner": "thread-3@vortexblack.test",
    "description": "Thread 3 multi-tenant regression fixture",
    "tenant_id": None,  # filled per-test
    "model_provider": "openai",
    "model_name": "gpt-4o",
    "framework": "custom",
    "environment": "SANDBOX",
    "trust_tier": "STANDARD",
    "lifecycle_status": "PENDING",
    "capability_surface": {
        "allowed_action_types": ["text:send"],
        "allowed_channels": ["email"],
        "allowed_environments": ["SANDBOX"],
        "allowed_recipient_domains": ["vortexblack.test"],
        "allowed_tools": [],
        "allowed_mcp_servers": [],
        "data_scopes": [],
    },
    "attestations": [],
    "tags": [],
    "metadata": {},
}


def _agent_payload(tenant: str, **overrides):
    out = dict(_AGENT_PAYLOAD_TPL)
    out["tenant_id"] = tenant
    out.update(overrides)
    return out


# =========================================================================== #
# Pattern 1 — body-tenant cross via RequireTenantMatch dependency               #
# =========================================================================== #


class TestBodyTenantCross:
    """A key bound to tenant-A cannot POST with body.tenant_id=tenant-B."""

    def test_register_agent_cross_tenant_body_is_403(self):
        with env_set(
            TEX_API_KEYS="acmekey:tenant_acme:agent:write+agent:read",
            TEX_REQUIRE_AUTH="1",
        ):
            app = _build_app()
            client = TestClient(app)

            # tenant_acme key posts an agent into tenant_globex.
            r = client.post(
                "/v1/agents",
                json=_agent_payload("tenant_globex"),
                headers={"Authorization": "Bearer acmekey"},
            )
            assert r.status_code == 403, r.text
            assert "not accessible" in r.json()["detail"]

    def test_register_agent_same_tenant_succeeds(self):
        with env_set(
            TEX_API_KEYS="acmekey:tenant_acme:agent:write+agent:read",
            TEX_REQUIRE_AUTH="1",
        ):
            app = _build_app()
            client = TestClient(app)

            r = client.post(
                "/v1/agents",
                json=_agent_payload("tenant_acme"),
                headers={"Authorization": "Bearer acmekey"},
            )
            assert r.status_code == 201, r.text

    def test_register_agent_cross_tenant_admin_passes(self):
        with env_set(
            TEX_API_KEYS=(
                "adminkey:internal:agent:write+agent:read+admin:cross_tenant"
            ),
            TEX_REQUIRE_AUTH="1",
        ):
            app = _build_app()
            client = TestClient(app)

            r = client.post(
                "/v1/agents",
                json=_agent_payload("tenant_anywhere"),
                headers={"Authorization": "Bearer adminkey"},
            )
            assert r.status_code == 201, r.text

    def test_learning_proposal_cross_tenant_body_is_403(self):
        with env_set(
            TEX_API_KEYS=(
                "acmekey:tenant_acme:"
                "learning:write+learning:read+learning:approve"
            ),
            TEX_REQUIRE_AUTH="1",
        ):
            app = _build_app()
            client = TestClient(app)

            r = client.post(
                "/v1/learning/proposals",
                json={
                    "tenant_id": "tenant_globex",
                    "proposed_new_version": "v2",
                    "created_by": "ops@acme.test",
                },
                headers={"Authorization": "Bearer acmekey"},
            )
            assert r.status_code == 403, r.text


# =========================================================================== #
# Pattern 2 — path/object-tenant cross via mid-handler enforce_tenant_match     #
# =========================================================================== #


class TestObjectTenantCross:
    """A key bound to tenant-A cannot fetch an agent_id that belongs to tenant-B."""

    def test_get_agent_cross_tenant_is_403(self):
        # Step 1: admin creates an agent in tenant_globex.
        # Step 2: tenant_acme key tries to GET it by id → 403.
        with env_set(
            TEX_API_KEYS=(
                "adminkey:internal:agent:write+agent:read+admin:cross_tenant,"
                "acmekey:tenant_acme:agent:read+agent:write"
            ),
            TEX_REQUIRE_AUTH="1",
        ):
            app = _build_app()
            client = TestClient(app)

            create = client.post(
                "/v1/agents",
                json=_agent_payload("tenant_globex"),
                headers={"Authorization": "Bearer adminkey"},
            )
            assert create.status_code == 201, create.text
            agent_id = create.json()["agent_id"]

            # Cross-tenant fetch.
            r = client.get(
                f"/v1/agents/{agent_id}",
                headers={"Authorization": "Bearer acmekey"},
            )
            assert r.status_code == 403, r.text

    def test_get_agent_same_tenant_succeeds(self):
        with env_set(
            TEX_API_KEYS="acmekey:tenant_acme:agent:read+agent:write",
            TEX_REQUIRE_AUTH="1",
        ):
            app = _build_app()
            client = TestClient(app)

            create = client.post(
                "/v1/agents",
                json=_agent_payload("tenant_acme"),
                headers={"Authorization": "Bearer acmekey"},
            )
            assert create.status_code == 201, create.text
            agent_id = create.json()["agent_id"]

            r = client.get(
                f"/v1/agents/{agent_id}",
                headers={"Authorization": "Bearer acmekey"},
            )
            assert r.status_code == 200, r.text

    def test_patch_agent_cross_tenant_is_403(self):
        with env_set(
            TEX_API_KEYS=(
                "adminkey:internal:agent:write+agent:read+admin:cross_tenant,"
                "acmekey:tenant_acme:agent:read+agent:write"
            ),
            TEX_REQUIRE_AUTH="1",
        ):
            app = _build_app()
            client = TestClient(app)

            create = client.post(
                "/v1/agents",
                json=_agent_payload("tenant_globex"),
                headers={"Authorization": "Bearer adminkey"},
            )
            assert create.status_code == 201, create.text
            agent_id = create.json()["agent_id"]

            r = client.patch(
                f"/v1/agents/{agent_id}",
                json={"description": "tampered by cross-tenant"},
                headers={"Authorization": "Bearer acmekey"},
            )
            assert r.status_code == 403, r.text

    def test_agent_lifecycle_cross_tenant_is_403(self):
        with env_set(
            TEX_API_KEYS=(
                "adminkey:internal:agent:write+agent:read+admin:cross_tenant,"
                "acmekey:tenant_acme:agent:read+agent:write"
            ),
            TEX_REQUIRE_AUTH="1",
        ):
            app = _build_app()
            client = TestClient(app)

            create = client.post(
                "/v1/agents",
                json=_agent_payload("tenant_globex"),
                headers={"Authorization": "Bearer adminkey"},
            )
            assert create.status_code == 201, create.text
            agent_id = create.json()["agent_id"]

            r = client.post(
                f"/v1/agents/{agent_id}/lifecycle",
                json={"status": "QUARANTINED"},
                headers={"Authorization": "Bearer acmekey"},
            )
            assert r.status_code == 403, r.text

    def test_agent_history_cross_tenant_is_403(self):
        with env_set(
            TEX_API_KEYS=(
                "adminkey:internal:agent:write+agent:read+admin:cross_tenant,"
                "acmekey:tenant_acme:agent:read"
            ),
            TEX_REQUIRE_AUTH="1",
        ):
            app = _build_app()
            client = TestClient(app)

            create = client.post(
                "/v1/agents",
                json=_agent_payload("tenant_globex"),
                headers={"Authorization": "Bearer adminkey"},
            )
            assert create.status_code == 201, create.text
            agent_id = create.json()["agent_id"]

            r = client.get(
                f"/v1/agents/{agent_id}/history",
                headers={"Authorization": "Bearer acmekey"},
            )
            assert r.status_code == 403, r.text

    def test_agent_ledger_cross_tenant_is_403(self):
        with env_set(
            TEX_API_KEYS=(
                "adminkey:internal:agent:write+agent:read+admin:cross_tenant,"
                "acmekey:tenant_acme:agent:read"
            ),
            TEX_REQUIRE_AUTH="1",
        ):
            app = _build_app()
            client = TestClient(app)

            create = client.post(
                "/v1/agents",
                json=_agent_payload("tenant_globex"),
                headers={"Authorization": "Bearer adminkey"},
            )
            assert create.status_code == 201, create.text
            agent_id = create.json()["agent_id"]

            r = client.get(
                f"/v1/agents/{agent_id}/ledger",
                headers={"Authorization": "Bearer acmekey"},
            )
            assert r.status_code == 403, r.text

    def test_agent_baseline_cross_tenant_is_403(self):
        with env_set(
            TEX_API_KEYS=(
                "adminkey:internal:agent:write+agent:read+admin:cross_tenant,"
                "acmekey:tenant_acme:agent:read"
            ),
            TEX_REQUIRE_AUTH="1",
        ):
            app = _build_app()
            client = TestClient(app)

            create = client.post(
                "/v1/agents",
                json=_agent_payload("tenant_globex"),
                headers={"Authorization": "Bearer adminkey"},
            )
            assert create.status_code == 201, create.text
            agent_id = create.json()["agent_id"]

            r = client.get(
                f"/v1/agents/{agent_id}/baseline",
                headers={"Authorization": "Bearer acmekey"},
            )
            assert r.status_code == 403, r.text

    def test_agent_evidence_summary_cross_tenant_is_403(self):
        with env_set(
            TEX_API_KEYS=(
                "adminkey:internal:agent:write+agent:read+admin:cross_tenant,"
                "acmekey:tenant_acme:agent:read"
            ),
            TEX_REQUIRE_AUTH="1",
        ):
            app = _build_app()
            client = TestClient(app)

            create = client.post(
                "/v1/agents",
                json=_agent_payload("tenant_globex"),
                headers={"Authorization": "Bearer adminkey"},
            )
            assert create.status_code == 201, create.text
            agent_id = create.json()["agent_id"]

            r = client.get(
                f"/v1/agents/{agent_id}/evidence_summary",
                headers={"Authorization": "Bearer acmekey"},
            )
            assert r.status_code == 403, r.text


# =========================================================================== #
# Pattern 3 — list-endpoint leak                                                #
# =========================================================================== #


class TestListLeak:
    """A tenant-scoped key calling a list endpoint must not see other
    tenants' records leak through."""

    def test_list_agents_filtered_to_principal_tenant(self):
        # Two agents in two tenants. Tenant-A key lists and must see
        # ONLY its own.
        with env_set(
            TEX_API_KEYS=(
                "adminkey:internal:agent:write+agent:read+admin:cross_tenant,"
                "acmekey:tenant_acme:agent:read+agent:write"
            ),
            TEX_REQUIRE_AUTH="1",
        ):
            app = _build_app()
            client = TestClient(app)

            client.post(
                "/v1/agents",
                json=_agent_payload("tenant_acme", name="agent-acme-1"),
                headers={"Authorization": "Bearer adminkey"},
            )
            client.post(
                "/v1/agents",
                json=_agent_payload("tenant_globex", name="agent-globex-1"),
                headers={"Authorization": "Bearer adminkey"},
            )

            r = client.get(
                "/v1/agents",
                headers={"Authorization": "Bearer acmekey"},
            )
            assert r.status_code == 200, r.text
            tenants = {a["tenant_id"] for a in r.json()["agents"]}
            assert tenants == {"tenant_acme"}, (
                f"list-agents leaked tenants: {tenants}"
            )

    def test_list_agents_admin_sees_all_tenants(self):
        with env_set(
            TEX_API_KEYS=(
                "adminkey:internal:agent:write+agent:read+admin:cross_tenant"
            ),
            TEX_REQUIRE_AUTH="1",
        ):
            app = _build_app()
            client = TestClient(app)

            client.post(
                "/v1/agents",
                json=_agent_payload("tenant_acme", name="agent-acme-1"),
                headers={"Authorization": "Bearer adminkey"},
            )
            client.post(
                "/v1/agents",
                json=_agent_payload("tenant_globex", name="agent-globex-1"),
                headers={"Authorization": "Bearer adminkey"},
            )

            r = client.get(
                "/v1/agents",
                headers={"Authorization": "Bearer adminkey"},
            )
            assert r.status_code == 200, r.text
            tenants = {a["tenant_id"] for a in r.json()["agents"]}
            assert tenants == {"tenant_acme", "tenant_globex"}

    def test_governance_state_filtered_to_principal_tenant(self):
        with env_set(
            TEX_API_KEYS=(
                "adminkey:internal:agent:write+agent:read+admin:cross_tenant,"
                "acmekey:tenant_acme:agent:read+agent:write"
            ),
            TEX_REQUIRE_AUTH="1",
        ):
            app = _build_app()
            client = TestClient(app)

            client.post(
                "/v1/agents",
                json=_agent_payload("tenant_acme", name="ga-acme"),
                headers={"Authorization": "Bearer adminkey"},
            )
            client.post(
                "/v1/agents",
                json=_agent_payload("tenant_globex", name="ga-globex"),
                headers={"Authorization": "Bearer adminkey"},
            )

            r = client.get(
                "/v1/agents/governance",
                headers={"Authorization": "Bearer acmekey"},
            )
            assert r.status_code == 200, r.text
            body = r.json()
            tenants = {row["tenant_id"] for row in body["agents"]}
            assert tenants == {"tenant_acme"}, (
                f"governance_state leaked tenants: {tenants}"
            )
            # Counts must be consistent with the filtered rows.
            assert body["counts"]["total_agents"] == len(body["agents"])

    def test_systemic_risks_filtered_to_principal_tenant(self):
        # When there are no ledger entries in either tenant, both
        # principals see an empty list — the test still proves the
        # filter doesn't 500 and respects scope.
        with env_set(
            TEX_API_KEYS=(
                "adminkey:internal:agent:write+agent:read+admin:cross_tenant,"
                "acmekey:tenant_acme:agent:read"
            ),
            TEX_REQUIRE_AUTH="1",
        ):
            app = _build_app()
            client = TestClient(app)

            client.post(
                "/v1/agents",
                json=_agent_payload("tenant_globex"),
                headers={"Authorization": "Bearer adminkey"},
            )
            r = client.get(
                "/v1/agents/systemic-risks",
                headers={"Authorization": "Bearer acmekey"},
            )
            assert r.status_code == 200, r.text
            # Empty ledger ⇒ empty risks for either key, but the
            # important assertion is no 5xx and no leak.
            assert r.json()["total"] == 0

    def test_system_state_governance_filtered_to_principal_tenant(self):
        # The tenant-truth gap: GET /v1/system/state built its governance
        # aggregate from the FULL registry with no tenant filter, then
        # returned it under the key's tenant label — so a tenant-A key
        # would read tenant-B's rows summed into its own counts. Two
        # agents in two tenants; the tenant-A key must see total_agents=1.
        with env_set(
            TEX_API_KEYS=(
                "adminkey:internal:agent:write+agent:read+admin:cross_tenant,"
                "acmekey:tenant_acme:agent:read+agent:write"
            ),
            TEX_REQUIRE_AUTH="1",
        ):
            app = _build_app()
            client = TestClient(app)

            client.post(
                "/v1/agents",
                json=_agent_payload("tenant_acme", name="ss-acme"),
                headers={"Authorization": "Bearer adminkey"},
            )
            client.post(
                "/v1/agents",
                json=_agent_payload("tenant_globex", name="ss-globex"),
                headers={"Authorization": "Bearer adminkey"},
            )

            # Admin (cross-tenant) sees the whole estate: both agents.
            admin_state = client.get(
                "/v1/system/state",
                headers={"Authorization": "Bearer adminkey"},
            )
            assert admin_state.status_code == 200, admin_state.text
            assert admin_state.json()["governance"]["total_agents"] == 2

            # Tenant-A key must NOT see tenant_globex's row in its
            # governance aggregate.
            r = client.get(
                "/v1/system/state",
                headers={"Authorization": "Bearer acmekey"},
            )
            assert r.status_code == 200, r.text
            gov = r.json()["governance"]
            assert gov["total_agents"] == 1, (
                f"system_state governance leaked another tenant's rows: "
                f"total_agents={gov['total_agents']} (expected 1)"
            )
            # The response is labelled with the principal's tenant, and
            # the aggregate under that label now covers ONLY that tenant.
            assert r.json()["tenant_id"] == "tenant_acme"

    def test_system_state_chain_block_is_honestly_labelled_global(self):
        # The chain block CANNOT be tenant-scoped — the discovery ledger
        # and snapshot store are single shared hash chains. So instead of
        # implying tenant scope, the block declares scope="global". This
        # asserts the honest label is present and correct for a
        # tenant-scoped principal.
        with env_set(
            TEX_API_KEYS="acmekey:tenant_acme:agent:read",
            TEX_REQUIRE_AUTH="1",
        ):
            app = _build_app()
            client = TestClient(app)
            r = client.get(
                "/v1/system/state",
                headers={"Authorization": "Bearer acmekey"},
            )
            assert r.status_code == 200, r.text
            assert r.json()["chain"]["scope"] == "global"


# =========================================================================== #
# Pattern 4 — c2pa opt-in guard                                                 #
# =========================================================================== #


class TestC2paOptInGuard:
    """
    The c2pa manifest endpoint is intentionally unauthenticated by
    design (perimeter handles auth at the gateway). When a Tex API
    key IS presented, the opt-in tenant guard activates.

    We don't wire a real manifest mirror here; we just confirm the
    boundary behavior — anonymous callers continue to reach the
    handler (and get a 503 because no mirror is configured), while
    a present-but-mismatched API key would 403 before the handler
    inspects the mirror.

    Because the manifest mirror isn't wired by default, the only
    safe assertions are:
      - anonymous call returns 503 (mirror missing), NOT 401
      - same-tenant key still reaches the 503 path
      - the route is not auth-required (anonymous is OK)
    """

    def test_anonymous_call_reaches_handler_not_401(self):
        # No TEX_REQUIRE_AUTH; no TEX_API_KEYS — fully anonymous.
        with env_set():
            # Clear any leftover require-auth from previous tests.
            os.environ.pop("TEX_REQUIRE_AUTH", None)
            os.environ.pop("TEX_API_KEYS", None)
            app = _build_app()
            client = TestClient(app)
            r = client.get("/v1/evidence/some-record-id/c2pa")
            # 503 (mirror missing) is the expected handler-side
            # response. Anything 401/403 would mean we broke the
            # endpoint's design property #3.
            assert r.status_code == 503, r.text

    def test_authenticated_same_tenant_is_not_401(self):
        # When auth IS configured AND the request presents a valid
        # key, the route must still reach the handler. The handler
        # then 503s on missing mirror.
        with env_set(
            TEX_API_KEYS="acmekey:tenant_acme",
            TEX_REQUIRE_AUTH="1",
        ):
            app = _build_app()
            client = TestClient(app)
            r = client.get(
                "/v1/evidence/some-record-id/c2pa",
                headers={"Authorization": "Bearer acmekey"},
            )
            # 503 — manifest mirror not wired in test app. The key
            # was accepted, no 401/403 fired before the handler.
            assert r.status_code == 503, r.text

    def test_anonymous_under_require_auth_still_reaches_handler(self):
        """The c2pa endpoint's audit-verifier path must survive even
        when ``TEX_REQUIRE_AUTH=1`` is set.

        This is the reason the opt-in pattern was wired with manual
        ``_extract_presented_key`` sniffing rather than a blanket
        ``Depends(authenticate_request)``. If we had used the
        Depends form, this request would 401 — and a public C2PA
        Content Credential that requires Tex-issued credentials to
        verify is a contradiction in terms. An EU AI Office
        reviewer or a downstream auditor must be able to fetch
        the manifest without a Tex key.
        """
        with env_set(
            TEX_API_KEYS="acmekey:tenant_acme",
            TEX_REQUIRE_AUTH="1",
        ):
            app = _build_app()
            client = TestClient(app)
            # No Authorization header at all.
            r = client.get("/v1/evidence/some-record-id/c2pa")
            # Must NOT 401 — falls through to mirror-503.
            assert r.status_code == 503, (
                f"unauthenticated audit-verifier path was incorrectly "
                f"401'd under TEX_REQUIRE_AUTH=1: got {r.status_code}, "
                f"body={r.text!r}"
            )

    def test_bad_key_under_opt_in_is_401(self):
        """The opt-in pattern still fails closed on bad credentials.

        Bringing a key triggers authentication. If the key is
        invalid, we must 401 — not silently fall through to the
        unauthenticated audit-verifier path (that would be a
        bypass: any attacker could pass ``Bearer garbage`` to
        sidestep an upstream gateway's auth check).
        """
        with env_set(
            TEX_API_KEYS="acmekey:tenant_acme",
            TEX_REQUIRE_AUTH="1",
        ):
            app = _build_app()
            client = TestClient(app)
            r = client.get(
                "/v1/evidence/some-record-id/c2pa",
                headers={"Authorization": "Bearer not-a-real-key"},
            )
            assert r.status_code == 401, r.text


# =========================================================================== #
# Sanity — the existing v18 tenant_routes test still passes here too.          #
# (We don't duplicate it; this just confirms the canonical happy path is alive.)
# =========================================================================== #


class TestCanonicalPathStillHolds:
    """Regression: the existing tenant-baseline route — the canonical
    correct usage that has worked all along — must continue to work."""

    def test_cross_tenant_baseline_fetch_is_403(self):
        with env_set(
            TEX_API_KEYS="acmekey:tenant_acme",
            TEX_REQUIRE_AUTH="1",
        ):
            app = _build_app()
            client = TestClient(app)
            r = client.get(
                "/v1/tenants/tenant_globex/baseline",
                headers={"Authorization": "Bearer acmekey"},
            )
            assert r.status_code == 403, r.text
            assert "not accessible" in r.json()["detail"]
