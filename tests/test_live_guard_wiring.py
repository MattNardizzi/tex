"""
Regression tripwire for the live-GUARD wiring (blueprint §3 boot bugs + §8 gaps).

Three code gaps were wired onto the live composition root so built-but-dormant
capabilities actually run, each SAFE-BY-DEFAULT behind an existing flag:

  * Gap 1 — the in-process PEP seals every ruling (TEX_SEAL_DECISIONS).
  * Gap 2 — the systemic-risk scorer is wired (TEX_ECOSYSTEM_SYSTEMIC).
  * Gap 3 — the reflexive governor is bound (TEX_SEAL_DECISIONS).

…and three boot bugs were fixed. These tests fail if a future change either
(a) turns a gap ON by default (unsafe) or (b) un-wires a gap so the flag no
longer activates it (the GUARD goes dark). They never bind the governor into
the shared process without unbinding it again — see the teardown below — so
they cannot pollute ``tests/test_reflexive_gov.py``'s leak check.
"""

from __future__ import annotations

import inspect
from types import SimpleNamespace

import tex.main as main
from tex.provenance.ledger import SealedFactLedger


# ── Boot bug 1: deferral is explicit-only (no swallowed-TypeError auto path) ──


def test_should_defer_runtime_is_explicit_only(monkeypatch):
    monkeypatch.delenv("TEX_DEFER_RUNTIME", raising=False)
    # Default: OFF. (The old auto path called the ``is_production_like``
    # @property as a function → TypeError swallowed → always False; this pins
    # the now-explicit contract so that regression cannot silently return.)
    assert main._should_defer_runtime() is False
    monkeypatch.setenv("TEX_DEFER_RUNTIME", "1")
    assert main._should_defer_runtime() is True
    monkeypatch.setenv("TEX_DEFER_RUNTIME", "yes")
    assert main._should_defer_runtime() is True
    monkeypatch.setenv("TEX_DEFER_RUNTIME", "0")
    assert main._should_defer_runtime() is False


# ── Boot bug 2: DiscoveryService is constructed exactly once ──────────────────


def test_discovery_service_built_once():
    src = inspect.getsource(main.build_runtime)
    assert src.count("DiscoveryService(") == 1, (
        "DiscoveryService must be constructed once; a duplicate allocation was "
        "shadowed (blueprint §3 boot bug)."
    )


# ── Boot bug 3: the imported-but-unused connectors are gone ───────────────────


def test_dead_connector_imports_removed():
    for name in (
        "KernelEbpfConnector",
        "CloudAuditConnector",
        "NetworkEgressConnector",
    ):
        assert not hasattr(main, name), (
            f"{name} was imported into tex.main but never instantiated — drop "
            "the dead import or wire it into _build_discovery_connectors."
        )


def test_live_connector_set_unchanged():
    # Dropping the dead imports must not change the live connector roster.
    classes = sorted({type(c).__name__ for c in main._build_discovery_connectors()})
    assert "OcsfAuditConnector" in classes
    assert "EntraConsentGraphConnector" in classes
    # The dropped planes must NOT appear (they were never instantiated).
    for absent in ("KernelEbpfConnector", "CloudAuditConnector", "NetworkEgressConnector"):
        assert absent not in classes


# ── Gap 2: the systemic-risk scorer is gated on TEX_ECOSYSTEM_SYSTEMIC ────────


def _engine_systemic(runtime):
    return runtime.ecosystem_bridge._engine._systemic


def test_systemic_scorer_off_by_default(monkeypatch, tmp_path):
    monkeypatch.delenv("TEX_ECOSYSTEM_SYSTEMIC", raising=False)
    runtime = main.build_runtime(evidence_path=tmp_path / "ev.jsonl")
    assert _engine_systemic(runtime) is None


def test_systemic_scorer_wired_under_flag(monkeypatch, tmp_path):
    from tex.systemic.risk_evaluator import SystemicRiskEvaluator

    monkeypatch.setenv("TEX_ECOSYSTEM_SYSTEMIC", "1")
    runtime = main.build_runtime(evidence_path=tmp_path / "ev.jsonl")
    assert isinstance(_engine_systemic(runtime), SystemicRiskEvaluator)


# ── Gaps 1 & 3: the reflexive-governor bind helper is gated on the ledger ─────


def _fake_app(decision_ledger):
    # _bind_reflexive_governor_if_enabled only reads app.state.decision_ledger.
    return SimpleNamespace(state=SimpleNamespace(decision_ledger=decision_ledger))


def test_bind_helper_is_noop_without_decision_ledger():
    """Default boot (TEX_SEAL_DECISIONS off → decision_ledger None): unbound."""
    from tex.selfgov.governor import reflexive_governor_bound

    assert not reflexive_governor_bound(), "governor leaked from a prior test"
    main._bind_reflexive_governor_if_enabled(
        _fake_app(None), SimpleNamespace(pdp=object())
    )
    assert not reflexive_governor_bound()


def test_bind_helper_binds_and_seals_under_decision_ledger():
    """TEX_SEAL_DECISIONS on (decision_ledger present): governor bound + sealed."""
    from tex.selfgov import governor as gov

    assert not gov.reflexive_governor_bound(), "governor leaked from a prior test"
    ledger = SealedFactLedger()
    # bind() only *stores* the duck-typed pdp (it does not call .evaluate() at
    # bind time), so a placeholder object is enough to prove the wiring.
    app = _fake_app(ledger)
    try:
        main._bind_reflexive_governor_if_enabled(app, SimpleNamespace(pdp=object()))
        assert gov.reflexive_governor_bound()
        # The bind ruling was sealed into the SAME ledger (one chain).
        assert len(ledger) >= 1
        assert ledger.verify_chain()["intact"] is True
        # Idempotent: a second call must NOT raise (re-bind-while-bound raises
        # by design) — the helper's reflexive_governor_bound() guard absorbs it.
        main._bind_reflexive_governor_if_enabled(app, SimpleNamespace(pdp=object()))
        assert gov.reflexive_governor_bound()
    finally:
        # Never leak a bound governor into the rest of the suite.
        if gov.reflexive_governor_bound():
            assert gov.unbind_reflexive_governor(gov._BINDING.token) is True
    assert not gov.reflexive_governor_bound()
