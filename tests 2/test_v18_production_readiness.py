"""
Production-readiness tests for V18:

  1. Scoped API keys grant only declared permissions.
  2. ``TEX_REQUIRE_AUTH=1`` forces authentication on every route.
  3. Tenant isolation rejects cross-tenant reads/writes by default.
  4. Learning/drift never auto-applies a calibration. Apply requires an
     explicit approver path.
  5. Evidence Postgres mirror + JSONL chain stay in sync structurally
     (mirror failure must not corrupt the JSONL chain).
"""

from __future__ import annotations

import importlib
import os
from contextlib import contextmanager
from pathlib import Path
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from tex.api import auth as auth_module


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


# =====================================================================
# Scoped keys / RBAC
# =====================================================================


class TestScopedKeys:
    def test_default_scopes_grant_decision_write_but_not_admin(self):
        with env_set(
            TEX_API_KEYS="acmekey:acme",
            TEX_REQUIRE_AUTH="1",
        ):
            app = _build_app()
            client = TestClient(app)

            # default scopes do NOT include policy:write
            r = client.post(
                "/policies/activate",
                json={"version": "default-v1"},
                headers={"Authorization": "Bearer acmekey"},
            )
            assert r.status_code == 403
            assert "policy:write" in r.json()["detail"]

    def test_explicit_policy_write_scope_grants_activation(self):
        with env_set(
            TEX_API_KEYS="adminkey:internal:policy:read+policy:write+admin:cross_tenant",
            TEX_REQUIRE_AUTH="1",
        ):
            app = _build_app()
            client = TestClient(app)

            # /policies/activate requires policy:write — this key has it
            r = client.post(
                "/policies/activate",
                json={"version": "nonexistent-version"},
                headers={"Authorization": "Bearer adminkey"},
            )
            # Activation will 404 for an unknown version, but the
            # important thing is auth/scope passed (not 401/403).
            assert r.status_code in (200, 400, 404)

    def test_missing_key_under_require_auth_is_401(self):
        with env_set(
            TEX_API_KEYS="anykey:t1",
            TEX_REQUIRE_AUTH="1",
        ):
            app = _build_app()
            client = TestClient(app)

            r = client.get("/health")
            # /health is unauthed by design (liveness probe)
            assert r.status_code == 200

            r = client.get("/decisions/00000000-0000-0000-0000-000000000000/replay")
            assert r.status_code == 401

    def test_require_auth_with_no_keys_configured_is_401(self):
        # TEX_REQUIRE_AUTH=1 with no keys means: refuse everything but
        # public probes.
        with env_set(TEX_REQUIRE_AUTH="1", TEX_API_KEYS=""):
            app = _build_app()
            client = TestClient(app)

            r = client.post(
                "/v1/learning/proposals",
                json={"source_policy_version": "x"},
                headers={"Authorization": "Bearer anything"},
            )
            assert r.status_code == 401


# =====================================================================
# Tenant isolation
# =====================================================================


class TestTenantIsolation:
    def test_cross_tenant_baseline_fetch_is_403(self):
        # acme key tries to read tenant_globex's baseline.
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
            assert r.status_code == 403
            assert "not accessible" in r.json()["detail"]

    def test_same_tenant_baseline_fetch_passes_auth(self):
        with env_set(
            TEX_API_KEYS="acmekey:tenant_acme:tenant:read",
            TEX_REQUIRE_AUTH="1",
        ):
            app = _build_app()
            client = TestClient(app)

            r = client.get(
                "/v1/tenants/tenant_acme/baseline",
                headers={"Authorization": "Bearer acmekey"},
            )
            # Even if the baseline is empty, auth + scope pass.
            assert r.status_code == 200

    def test_admin_cross_tenant_can_read_any_tenant(self):
        with env_set(
            TEX_API_KEYS="adminkey:internal:tenant:read+admin:cross_tenant",
            TEX_REQUIRE_AUTH="1",
        ):
            app = _build_app()
            client = TestClient(app)

            r = client.get(
                "/v1/tenants/tenant_acme/baseline",
                headers={"Authorization": "Bearer adminkey"},
            )
            assert r.status_code == 200


# =====================================================================
# Learning gate — never auto-applies
# =====================================================================


class TestLearningApprovalGate:
    def test_orchestrator_apply_proposal_requires_explicit_approver(self):
        """
        The FeedbackLoopOrchestrator.apply_proposal MUST require an
        explicit approver string. There is no API path or env flag
        that bypasses this. This is the structural enforcement of
        Item #4.
        """
        from tex.learning.feedback_loop import FeedbackLoopOrchestrator

        # Inspect the signature to confirm 'approver' is keyword-only and required.
        import inspect
        sig = inspect.signature(FeedbackLoopOrchestrator.apply_proposal)
        approver = sig.parameters.get("approver")
        assert approver is not None
        assert approver.kind == inspect.Parameter.KEYWORD_ONLY
        # No default → caller MUST pass it.
        assert approver.default is inspect.Parameter.empty

    def test_no_auto_apply_codepaths_in_learning_layer(self):
        """
        Grep-level guarantee: there is no symbol named ``auto_apply``,
        ``auto_approve``, or ``auto_activate`` in the learning layer.
        If anyone ever introduces one, this test fails until it is
        explicitly removed.
        """
        learning_dir = Path(__file__).resolve().parents[1] / "src" / "tex" / "learning"
        forbidden_substrings = ("auto_apply", "auto_approve", "auto_activate")
        offenders: list[tuple[Path, str]] = []
        for path in learning_dir.rglob("*.py"):
            text = path.read_text(encoding="utf-8")
            for needle in forbidden_substrings:
                if needle in text:
                    offenders.append((path, needle))
        assert not offenders, (
            f"learning layer contains forbidden auto-apply hooks: {offenders}"
        )


# =====================================================================
# Evidence: JSONL stays the source of truth even when mirror fails
# =====================================================================


class TestEvidenceMirrorIsolation:
    def test_mirror_failure_does_not_corrupt_jsonl_chain(self, tmp_path):
        """
        A misbehaving mirror must NEVER block or corrupt the JSONL
        chain. The recorder swallows mirror errors and keeps the
        chain intact.
        """
        from tex.domain.decision import Decision
        from tex.domain.verdict import Verdict
        from tex.evidence.recorder import EvidenceRecorder

        class ExplodingMirror:
            def record(self, _record):
                raise RuntimeError("simulated mirror outage")

        path = tmp_path / "evidence.jsonl"
        recorder = EvidenceRecorder(path, mirror=ExplodingMirror())

        decision = Decision(
            request_id=uuid4(),
            verdict=Verdict.PERMIT,
            confidence=0.9,
            final_score=0.1,
            action_type="email_send",
            channel="smtp",
            environment="prod",
            content_excerpt="hello world",
            content_sha256="a" * 64,
            policy_version="v1",
            scores={"deterministic": 0.0},
            reasons=[],
            uncertainty_flags=[],
        )
        # Should NOT raise even though the mirror raises.
        rec = recorder.record_decision(decision)
        assert rec.record_hash
        # And the JSONL on disk must contain the record.
        assert path.exists()
        contents = path.read_text(encoding="utf-8").strip().splitlines()
        assert len(contents) == 1
