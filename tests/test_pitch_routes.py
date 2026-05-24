"""
Thread 4 — Layer 5 export route regression tests.

Tex is a five-layer AI agent governance platform. These tests cover
the three Layer 5 (Reporting / Documenting / Logging) HTTP endpoints
that expose the signed evidence chain to outside parties:

  - ``/v1/exports/insurer`` — offline-verifiable signed packet for any
    third party (insurer, EU AI Act QMS auditor, NAIC examiner,
    customer security review, internal compliance, downstream regulator)
  - ``/v1/exports/ciso`` — MCP-runtime risk view for the security team
    running the company's agents
  - ``/v1/exports/vp-marketing`` — brand-safety / disclosure view for
    teams running customer-facing AI agents

Proof that:

  1. The three routes exist and are reachable.
  2. Authentication is required (401 for unauthenticated callers).
  3. Scope is required (403 for keys lacking ``evidence:export``).
  4. Cross-tenant body submission to the insurer route is rejected by
     ``RequireTenantMatch`` BEFORE the handler runs (Thread 3 BOLA
     defence, OWASP API #1).
  5. Malformed input is rejected with 422 (FastAPI / Pydantic v2).
  6. The insurer packet returned round-trips through the independent
     ``tex.pitch.verifier.verify_insurer_evidence_packet`` — i.e. the
     packet you get over HTTP is bit-for-bit verifiable offline.
  7. The circular-import workaround is no longer required: a fresh
     interpreter can ``from tex.pitch import build_insurer_evidence_packet``
     without first importing ``tex.ecosystem``.

Same harness shape as ``test_multi_tenant_enforcement.py``:
``env_set`` context manager + per-test ``importlib.reload`` of
``tex.main`` so each test runs against a fresh ``create_app()``.
"""

from __future__ import annotations

import base64
import importlib
import os
import subprocess
import sys
from contextlib import contextmanager

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


# --------------------------------------------------------------------------- #
# Circular-import regression                                                    #
# --------------------------------------------------------------------------- #


class TestCircularImportFixed:
    """The pitch package must import without a pre-import of tex.ecosystem."""

    def test_direct_pitch_import_in_fresh_interpreter(self):
        """
        Run a subprocess that imports tex.pitch *without* first
        importing tex.ecosystem. Before Thread 4 this raised
        ``ImportError: cannot import name 'CryptoProvenance' from
        partially initialized module 'tex.events.crypto_provenance'``.
        """
        result = subprocess.run(
            [
                sys.executable,
                "-c",
                (
                    "from tex.pitch import ("
                    "build_insurer_evidence_packet, "
                    "build_mcp_risk_dossier, "
                    "build_brand_safety_dossier); "
                    "print('ok')"
                ),
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert result.returncode == 0, (
            "fresh-interpreter import of tex.pitch failed:\n"
            f"stdout: {result.stdout!r}\nstderr: {result.stderr!r}"
        )
        assert "ok" in result.stdout

    def test_engine_module_still_has_provenance_param(self):
        """
        The TYPE_CHECKING move must not have broken the constructor
        signature. The engine still accepts ``provenance`` as a kw.
        """
        from tex.ecosystem.engine import EcosystemEngine
        import inspect

        sig = inspect.signature(EcosystemEngine.__init__)
        assert "provenance" in sig.parameters


# --------------------------------------------------------------------------- #
# Route registration                                                            #
# --------------------------------------------------------------------------- #


class TestRoutesRegistered:
    """The three pitch routes must be reachable on a fresh create_app()."""

    def test_all_three_paths_present(self):
        with env_set(TEX_ALLOW_SEMANTIC_FALLBACK="true"):
            app = _build_app()
            paths = {r.path for r in app.routes if hasattr(r, "path")}
            assert "/v1/exports/vp-marketing" in paths
            assert "/v1/exports/ciso" in paths
            assert "/v1/exports/insurer" in paths


# --------------------------------------------------------------------------- #
# Authentication: anonymous traffic                                              #
# --------------------------------------------------------------------------- #


class TestAuthenticationRequired:
    """Without TEX_REQUIRE_AUTH=1, anonymous traffic passes by design.
    With it set, all three routes 401 the anonymous caller."""

    def test_vp_marketing_401_when_auth_required(self):
        with env_set(
            TEX_REQUIRE_AUTH="1",
            TEX_API_KEYS="anykey:tenant_a:evidence:export",
            TEX_ALLOW_SEMANTIC_FALLBACK="true",
        ):
            app = _build_app()
            client = TestClient(app)
            r = client.post(
                "/v1/exports/vp-marketing",
                json={"company_domain": "example.com"},
            )
            assert r.status_code == 401, r.text

    def test_ciso_401_when_auth_required(self):
        with env_set(
            TEX_REQUIRE_AUTH="1",
            TEX_API_KEYS="anykey:tenant_a:evidence:export",
            TEX_ALLOW_SEMANTIC_FALLBACK="true",
        ):
            app = _build_app()
            client = TestClient(app)
            r = client.post(
                "/v1/exports/ciso",
                json={"company_domain": "example.com"},
            )
            assert r.status_code == 401, r.text

    def test_insurer_401_when_auth_required(self):
        with env_set(
            TEX_REQUIRE_AUTH="1",
            TEX_API_KEYS="anykey:tenant_a:evidence:export",
            TEX_ALLOW_SEMANTIC_FALLBACK="true",
        ):
            app = _build_app()
            client = TestClient(app)
            r = client.post(
                "/v1/exports/insurer",
                json={
                    "tenant_id": "tenant_a",
                    "period_start_iso": "2026-04-01T00:00:00Z",
                    "period_end_iso": "2026-05-01T00:00:00Z",
                },
            )
            assert r.status_code == 401, r.text


# --------------------------------------------------------------------------- #
# Scope gate: missing evidence:export → 403                                     #
# --------------------------------------------------------------------------- #


class TestScopeRequired:
    """A key without ``evidence:export`` must 403."""

    def test_vp_marketing_without_scope_is_403(self):
        with env_set(
            TEX_REQUIRE_AUTH="1",
            # No evidence:export, only a read scope.
            TEX_API_KEYS="weakkey:tenant_a:agent:read",
            TEX_ALLOW_SEMANTIC_FALLBACK="true",
        ):
            app = _build_app()
            client = TestClient(app)
            r = client.post(
                "/v1/exports/vp-marketing",
                json={"company_domain": "example.com"},
                headers={"Authorization": "Bearer weakkey"},
            )
            assert r.status_code == 403, r.text
            assert "evidence:export" in r.json()["detail"]

    def test_ciso_without_scope_is_403(self):
        with env_set(
            TEX_REQUIRE_AUTH="1",
            TEX_API_KEYS="weakkey:tenant_a:agent:read",
            TEX_ALLOW_SEMANTIC_FALLBACK="true",
        ):
            app = _build_app()
            client = TestClient(app)
            r = client.post(
                "/v1/exports/ciso",
                json={"company_domain": "example.com"},
                headers={"Authorization": "Bearer weakkey"},
            )
            assert r.status_code == 403, r.text

    def test_insurer_without_scope_is_403(self):
        with env_set(
            TEX_REQUIRE_AUTH="1",
            TEX_API_KEYS="weakkey:tenant_a:agent:read",
            TEX_ALLOW_SEMANTIC_FALLBACK="true",
        ):
            app = _build_app()
            client = TestClient(app)
            r = client.post(
                "/v1/exports/insurer",
                json={
                    "tenant_id": "tenant_a",
                    "period_start_iso": "2026-04-01T00:00:00Z",
                    "period_end_iso": "2026-05-01T00:00:00Z",
                },
                headers={"Authorization": "Bearer weakkey"},
            )
            assert r.status_code == 403, r.text


# --------------------------------------------------------------------------- #
# Tenant boundary: insurer route rejects cross-tenant body                      #
# --------------------------------------------------------------------------- #


class TestInsurerCrossTenantBlocked:
    """Pre-handler RequireTenantMatch must 403 cross-tenant body submission."""

    def test_cross_tenant_body_is_403(self):
        with env_set(
            TEX_REQUIRE_AUTH="1",
            TEX_API_KEYS="acmekey:tenant_acme:evidence:export",
            TEX_ALLOW_SEMANTIC_FALLBACK="true",
        ):
            app = _build_app()
            client = TestClient(app)
            r = client.post(
                "/v1/exports/insurer",
                json={
                    # tenant_acme key posts a packet for tenant_globex
                    "tenant_id": "tenant_globex",
                    "period_start_iso": "2026-04-01T00:00:00Z",
                    "period_end_iso": "2026-05-01T00:00:00Z",
                },
                headers={"Authorization": "Bearer acmekey"},
            )
            assert r.status_code == 403, r.text
            assert "not accessible" in r.json()["detail"]

    def test_same_tenant_body_succeeds(self):
        with env_set(
            TEX_REQUIRE_AUTH="1",
            TEX_API_KEYS="acmekey:tenant_acme:evidence:export",
            TEX_ALLOW_SEMANTIC_FALLBACK="true",
            # Force ed25519 so we don't depend on liboqs presence in CI.
            TEX_PITCH_SIGNING_ALGORITHM="ed25519",
        ):
            app = _build_app()
            client = TestClient(app)
            r = client.post(
                "/v1/exports/insurer",
                json={
                    "tenant_id": "tenant_acme",
                    "period_start_iso": "2026-04-01T00:00:00Z",
                    "period_end_iso": "2026-05-01T00:00:00Z",
                },
                headers={"Authorization": "Bearer acmekey"},
            )
            assert r.status_code == 200, r.text

    def test_cross_tenant_admin_passes(self):
        with env_set(
            TEX_REQUIRE_AUTH="1",
            TEX_API_KEYS=(
                "adminkey:internal:evidence:export+admin:cross_tenant"
            ),
            TEX_ALLOW_SEMANTIC_FALLBACK="true",
            TEX_PITCH_SIGNING_ALGORITHM="ed25519",
        ):
            app = _build_app()
            client = TestClient(app)
            r = client.post(
                "/v1/exports/insurer",
                json={
                    "tenant_id": "tenant_arbitrary",
                    "period_start_iso": "2026-04-01T00:00:00Z",
                    "period_end_iso": "2026-05-01T00:00:00Z",
                },
                headers={"Authorization": "Bearer adminkey"},
            )
            assert r.status_code == 200, r.text


# --------------------------------------------------------------------------- #
# Happy-path bodies                                                              #
# --------------------------------------------------------------------------- #


class TestHappyPathSuccess:
    """Authenticated, scoped, in-tenant calls return well-formed packets."""

    def test_vp_marketing_returns_dossier(self):
        with env_set(
            TEX_REQUIRE_AUTH="1",
            TEX_API_KEYS="acmekey:tenant_acme:evidence:export",
            TEX_ALLOW_SEMANTIC_FALLBACK="true",
        ):
            app = _build_app()
            client = TestClient(app)
            r = client.post(
                "/v1/exports/vp-marketing",
                json={"company_domain": "stemwave.com"},
                headers={"Authorization": "Bearer acmekey"},
            )
            assert r.status_code == 200, r.text
            body = r.json()
            assert body["dossier_kind"] == "brand_safety"
            assert body["requesting_tenant"] == "tenant_acme"
            dossier = body["dossier"]
            assert "company_name" in dossier
            assert "enforcement_actions" in dossier
            assert "regulatory_anchors" in dossier
            assert "tex_evidence_capabilities" in dossier

    def test_ciso_returns_dossier(self):
        with env_set(
            TEX_REQUIRE_AUTH="1",
            TEX_API_KEYS="acmekey:tenant_acme:evidence:export",
            TEX_ALLOW_SEMANTIC_FALLBACK="true",
        ):
            app = _build_app()
            client = TestClient(app)
            r = client.post(
                "/v1/exports/ciso",
                json={"company_domain": "stemwave.com"},
                headers={"Authorization": "Bearer acmekey"},
            )
            assert r.status_code == 200, r.text
            body = r.json()
            assert body["dossier_kind"] == "mcp_risk"
            assert body["requesting_tenant"] == "tenant_acme"
            dossier = body["dossier"]
            assert "company_name" in dossier
            assert "cve_exposure" in dossier
            assert len(dossier["cve_exposure"]) == 4  # four canonical CVEs
            assert "ssrf_risk_score" in dossier
            assert "bluerock_ssrf_fraction" in dossier
            assert dossier["bluerock_ssrf_fraction"] == pytest.approx(0.367, abs=1e-6)
            assert "tex_runtime_capabilities" in dossier

    def test_insurer_returns_signed_packet(self):
        with env_set(
            TEX_REQUIRE_AUTH="1",
            TEX_API_KEYS="acmekey:tenant_acme:evidence:export",
            TEX_ALLOW_SEMANTIC_FALLBACK="true",
            TEX_PITCH_SIGNING_ALGORITHM="ed25519",
        ):
            app = _build_app()
            client = TestClient(app)
            r = client.post(
                "/v1/exports/insurer",
                json={
                    "tenant_id": "tenant_acme",
                    "period_start_iso": "2026-04-01T00:00:00Z",
                    "period_end_iso": "2026-05-01T00:00:00Z",
                },
                headers={"Authorization": "Bearer acmekey"},
            )
            assert r.status_code == 200, r.text
            body = r.json()
            assert body["packet_kind"] == "insurer_evidence_packet"
            packet = body["packet"]
            assert packet["tenant_id"] == "tenant_acme"
            assert packet["period_start_iso"] == "2026-04-01T00:00:00Z"
            assert packet["period_end_iso"] == "2026-05-01T00:00:00Z"
            assert packet["algorithm"] == "ed25519"
            assert packet["layout_version"] == "1"
            # Three canonical artifact slots.
            assert set(packet["artifact_digests"].keys()) == {
                "audit_chain",
                "c2pa_manifests",
                "tool_receipts",
            }
            assert set(packet["artifacts_b64"].keys()) == set(
                packet["artifact_digests"].keys()
            )
            assert len(packet["manifest_signature_b64"]) > 0
            assert len(packet["signing_public_key_b64"]) > 0


# --------------------------------------------------------------------------- #
# Round-trip: returned packet verifies independently                            #
# --------------------------------------------------------------------------- #


class TestInsurerPacketRoundTrip:
    """The HTTP-returned packet must round-trip through the verifier."""

    def test_packet_round_trips_via_verifier(self):
        from tex.pitch import (
            InsurerEvidencePacket,
            verify_insurer_evidence_packet,
        )
        from tex.pqcrypto.algorithm_agility import SignatureAlgorithm

        with env_set(
            TEX_REQUIRE_AUTH="1",
            TEX_API_KEYS="acmekey:tenant_acme:evidence:export",
            TEX_ALLOW_SEMANTIC_FALLBACK="true",
            TEX_PITCH_SIGNING_ALGORITHM="ed25519",
        ):
            app = _build_app()
            client = TestClient(app)
            r = client.post(
                "/v1/exports/insurer",
                json={
                    "tenant_id": "tenant_acme",
                    "period_start_iso": "2026-04-01T00:00:00Z",
                    "period_end_iso": "2026-05-01T00:00:00Z",
                },
                headers={"Authorization": "Bearer acmekey"},
            )
            assert r.status_code == 200, r.text
            packet_json = r.json()["packet"]

            # Reconstitute the InsurerEvidencePacket dataclass from the
            # JSON envelope and feed it to the independent verifier.
            artifacts = {
                name: base64.b64decode(b64)
                for name, b64 in packet_json["artifacts_b64"].items()
            }
            reconstituted = InsurerEvidencePacket(
                tenant_id=packet_json["tenant_id"],
                period_start_iso=packet_json["period_start_iso"],
                period_end_iso=packet_json["period_end_iso"],
                algorithm=SignatureAlgorithm(packet_json["algorithm"]),
                layout_version=packet_json["layout_version"],
                artifacts=artifacts,
                artifact_digests=dict(packet_json["artifact_digests"]),
                manifest_signature_b64=packet_json["manifest_signature_b64"],
                signing_public_key=base64.b64decode(packet_json["signing_public_key_b64"]),
            )
            result = verify_insurer_evidence_packet(reconstituted)
            assert result.is_valid, (
                f"verifier rejected the HTTP packet: "
                f"issues={result.issues!r}"
            )


# --------------------------------------------------------------------------- #
# Input validation                                                              #
# --------------------------------------------------------------------------- #


class TestInputValidation:
    """Malformed bodies → 422."""

    def test_vp_marketing_missing_company_domain_is_422(self):
        with env_set(
            TEX_REQUIRE_AUTH="1",
            TEX_API_KEYS="acmekey:tenant_acme:evidence:export",
            TEX_ALLOW_SEMANTIC_FALLBACK="true",
        ):
            app = _build_app()
            client = TestClient(app)
            r = client.post(
                "/v1/exports/vp-marketing",
                json={},
                headers={"Authorization": "Bearer acmekey"},
            )
            assert r.status_code == 422, r.text

    def test_ciso_extra_fields_is_422(self):
        with env_set(
            TEX_REQUIRE_AUTH="1",
            TEX_API_KEYS="acmekey:tenant_acme:evidence:export",
            TEX_ALLOW_SEMANTIC_FALLBACK="true",
        ):
            app = _build_app()
            client = TestClient(app)
            r = client.post(
                "/v1/exports/ciso",
                json={
                    "company_domain": "example.com",
                    "rogue_field": "smuggled",
                },
                headers={"Authorization": "Bearer acmekey"},
            )
            assert r.status_code == 422, r.text

    def test_insurer_empty_tenant_is_400_or_422(self):
        with env_set(
            TEX_REQUIRE_AUTH="1",
            TEX_API_KEYS="acmekey:tenant_acme:evidence:export",
            TEX_ALLOW_SEMANTIC_FALLBACK="true",
        ):
            app = _build_app()
            client = TestClient(app)
            r = client.post(
                "/v1/exports/insurer",
                json={
                    "tenant_id": "",
                    "period_start_iso": "2026-04-01T00:00:00Z",
                    "period_end_iso": "2026-05-01T00:00:00Z",
                },
                headers={"Authorization": "Bearer acmekey"},
            )
            # Pydantic min_length=1 enforces 422; pre-handler dependency
            # may also reject. Either is acceptable for this guard.
            assert r.status_code in (400, 403, 422), r.text


# --------------------------------------------------------------------------- #
# Signing algorithm selection                                                   #
# --------------------------------------------------------------------------- #


class TestSigningAlgorithmSelection:
    """Operator can override the default ML-DSA-65 via env."""

    def test_explicit_ed25519_is_honored(self):
        with env_set(
            TEX_REQUIRE_AUTH="1",
            TEX_API_KEYS="acmekey:tenant_acme:evidence:export",
            TEX_ALLOW_SEMANTIC_FALLBACK="true",
            TEX_PITCH_SIGNING_ALGORITHM="ed25519",
        ):
            app = _build_app()
            client = TestClient(app)
            r = client.post(
                "/v1/exports/insurer",
                json={
                    "tenant_id": "tenant_acme",
                    "period_start_iso": "2026-04-01T00:00:00Z",
                    "period_end_iso": "2026-05-01T00:00:00Z",
                },
                headers={"Authorization": "Bearer acmekey"},
            )
            assert r.status_code == 200, r.text
            assert r.json()["packet"]["algorithm"] == "ed25519"

    def test_unknown_algorithm_is_500(self):
        with env_set(
            TEX_REQUIRE_AUTH="1",
            TEX_API_KEYS="acmekey:tenant_acme:evidence:export",
            TEX_ALLOW_SEMANTIC_FALLBACK="true",
            TEX_PITCH_SIGNING_ALGORITHM="not-a-real-algorithm",
        ):
            app = _build_app()
            client = TestClient(app)
            r = client.post(
                "/v1/exports/insurer",
                json={
                    "tenant_id": "tenant_acme",
                    "period_start_iso": "2026-04-01T00:00:00Z",
                    "period_end_iso": "2026-05-01T00:00:00Z",
                },
                headers={"Authorization": "Bearer acmekey"},
            )
            assert r.status_code == 500, r.text
            assert "TEX_PITCH_SIGNING_ALGORITHM" in r.json()["detail"]
