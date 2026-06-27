"""
E1 — the /v1/ask ENFORCEMENT-PLANE path must answer ONLY from a SEALED plane
snapshot, or ABSTAIN — never a free guess and NEVER by reading live state.

These tests drive ``voice_ask.answer_question`` against an app.state carrying a
real ``SealedFactLedger`` seeded with PLANE facts, and assert:

  * flag-ON (a sealed PLANE fact) → the spoken answer states the sealed plane
    (DECIDE-ONLY / CREDENTIAL-ENFORCED / IN-PATH-BLOCKING), gate PERMIT;
  * no sealed PLANE fact for the named agent → authored ABSTAIN (never a guessed
    DECIDE-ONLY);
  * ledger None (default boot) → ABSTAIN;
  * the freshest snapshot (max captured_at) wins;
  * the answer path NEVER reads the live PlaneSignalRegistry — a registry that
    would derive a DIFFERENT plane than the sealed fact does not change the answer.
"""

from __future__ import annotations

import types

from tex.domain.verdict import Verdict
from tex.governance.plane_signals import (
    PLANE_CREDENTIAL_ENFORCED,
    PLANE_DECIDE_ONLY,
    PLANE_IN_PATH_BLOCKING,
    PlaneSignalRegistry,
)
from tex.provenance.ledger import SealedFactLedger
from tex.provenance.plane_seal import seal_plane
from tex.voice import answer_forms, voice_ask


def _request(*, ledger=None, registry=None) -> types.SimpleNamespace:
    state = types.SimpleNamespace(decision_store=None, decision_ledger=ledger)
    if registry is not None:
        state.plane_signal_registry = registry
    return types.SimpleNamespace(app=types.SimpleNamespace(state=state))


_Q = "is AtlasPay credential-enforced or decide-only"


# ─────────────────────────────── default-OFF / inert ───────────────────────────
def test_no_ledger_abstains() -> None:
    # Default boot: decision_ledger is None → the plane branch ABSTAINs.
    out = voice_ask.answer_question(_request(ledger=None), transcript=_Q, tenant=None)
    assert out.verdict is Verdict.ABSTAIN
    assert out.answer == answer_forms.ABSTAIN_NO_PLANE
    assert out.routed_dimension == "plane"


def test_no_sealed_plane_fact_abstains_never_guesses() -> None:
    # Ledger present but EMPTY of PLANE facts for this agent → ABSTAIN, not a
    # confidently-wrong "DECIDE-ONLY".
    ledger = SealedFactLedger()
    seal_plane(ledger, "OtherAgent", PLANE_DECIDE_ONLY,
               tenant="acme", last_handshake_ts=None, captured_at=1.0,
               agent_name="OtherAgent")
    out = voice_ask.answer_question(_request(ledger=ledger), transcript=_Q, tenant=None)
    assert out.verdict is Verdict.ABSTAIN
    assert out.answer == answer_forms.ABSTAIN_NO_PLANE


# ─────────────────────────── answers from the sealed plane ─────────────────────
def test_sealed_decide_only_is_answered() -> None:
    ledger = SealedFactLedger()
    seal_plane(ledger, "AtlasPay", PLANE_DECIDE_ONLY,
               tenant="acme", last_handshake_ts=None, captured_at=42.0,
               agent_name="AtlasPay")
    out = voice_ask.answer_question(_request(ledger=ledger), transcript=_Q, tenant=None)
    assert out.verdict is Verdict.PERMIT
    assert out.answer == "Agent AtlasPay is on the DECIDE-ONLY enforcement plane, observed as of 42.0."
    assert out.routed_dimension == "plane"
    assert out.gate["verdict"] == "PERMIT"
    assert out.attestation_anchor and len(out.attestation_anchor) == 64


def test_sealed_credential_enforced_is_answered() -> None:
    ledger = SealedFactLedger()
    seal_plane(ledger, "AtlasPay", PLANE_CREDENTIAL_ENFORCED,
               tenant="acme", last_handshake_ts=10.0, captured_at=42.0,
               agent_name="AtlasPay")
    out = voice_ask.answer_question(_request(ledger=ledger), transcript=_Q, tenant=None)
    assert out.verdict is Verdict.PERMIT
    assert "CREDENTIAL-ENFORCED" in out.answer


def test_sealed_in_path_blocking_is_answered() -> None:
    ledger = SealedFactLedger()
    seal_plane(ledger, "AtlasPay", PLANE_IN_PATH_BLOCKING,
               tenant="acme", last_handshake_ts=None, captured_at=42.0,
               agent_name="AtlasPay")
    out = voice_ask.answer_question(
        _request(ledger=ledger), transcript="what enforcement plane is AtlasPay on", tenant=None)
    assert out.verdict is Verdict.PERMIT
    assert "IN-PATH-BLOCKING" in out.answer


# ─────────────────────────────── freshest wins ─────────────────────────────────
def test_freshest_snapshot_wins() -> None:
    ledger = SealedFactLedger()
    # Stale CREDENTIAL-ENFORCED, then a fresher DECIDE-ONLY (a downgrade observed
    # later) — the freshest captured_at must win.
    seal_plane(ledger, "AtlasPay", PLANE_CREDENTIAL_ENFORCED,
               tenant="acme", last_handshake_ts=5.0, captured_at=5.0, agent_name="AtlasPay")
    seal_plane(ledger, "AtlasPay", PLANE_DECIDE_ONLY,
               tenant="acme", last_handshake_ts=None, captured_at=99.0, agent_name="AtlasPay")
    out = voice_ask.answer_question(_request(ledger=ledger), transcript=_Q, tenant=None)
    assert out.verdict is Verdict.PERMIT
    assert "DECIDE-ONLY" in out.answer
    assert "observed as of 99.0" in out.answer


# ─────────────── the answer path NEVER reads the live registry ──────────────────
def test_answer_path_ignores_live_registry() -> None:
    # The sealed fact says DECIDE-ONLY; the LIVE registry would derive
    # CREDENTIAL-ENFORCED for the same agent. The SEALED value must win — proving
    # the answer path reads the ledger, not the registry.
    ledger = SealedFactLedger()
    seal_plane(ledger, "AtlasPay", PLANE_DECIDE_ONLY,
               tenant="acme", last_handshake_ts=None, captured_at=1.0, agent_name="AtlasPay")
    live = PlaneSignalRegistry()
    live.record_handshake("AtlasPay", "acme", "ledgerd")  # would derive CREDENTIAL-ENFORCED
    assert live.derive("AtlasPay", "acme").plane == PLANE_CREDENTIAL_ENFORCED

    out = voice_ask.answer_question(
        _request(ledger=ledger, registry=live), transcript=_Q, tenant=None)
    assert out.verdict is Verdict.PERMIT
    assert "DECIDE-ONLY" in out.answer
    assert "CREDENTIAL-ENFORCED" not in out.answer


def test_answer_path_does_not_import_or_read_the_live_registry() -> None:
    # Structural guarantee: the /v1/ask answer module never imports the live
    # PlaneSignalRegistry, never reads app.state.plane_signal_registry, and never
    # calls .derive(). The producer (plane_seal.snapshot_planes) is the only place
    # the live registry is touched — the answer is sealed-fact-only by construction.
    import re
    from pathlib import Path

    src = Path(voice_ask.__file__).read_text()
    assert not re.search(r"import.*PlaneSignalRegistry", src)
    assert "plane_signal_registry" not in src
    assert "plane_signals" not in src
    assert ".derive(" not in src
