"""v5 — the regulator-grade STRONG path (COSE-signed evidence-chain seal).

When a decision is resolvable and a full evidence recorder + signing key are
present, a decision-backed attribution additionally seals a first-class,
COSE-signed row into the main evidence chain (see
``CausalAttributionPort._maybe_seal_decision_attribution``).

REGRESSION GUARD: that method imports ``mint_signed_statement`` from
``tex.evidence.scitt_statement``. It previously imported from a non-existent
``tex.evidence.signed_statement``; the ImportError was swallowed by the
method's ``except Exception: return None``, so the strong path ALWAYS returned
None and never sealed an attribution — silently dead code. These tests drive
the path end-to-end with a REAL SCITT mint, so a broken import (or any other
silent-swallow) makes them fail instead of degrading invisibly.
"""

from __future__ import annotations

import uuid
from typing import Any

from tex.evidence.scitt_cose_alg import cose_alg_for
from tex.pqcrypto._ed25519_provider import Ed25519Provider
from tex.vigil.causal import CausalAttributionPort
from tex.vigil.dimensions import DimensionReading, ProofRef


class _FakeRootCause:
    agent_id = "agent-omega"


class _FakeAttributionResult:
    primary_root_cause = _FakeRootCause()
    attribution_method = "hcg+counterfactual"


class _FakeEvidenceRecord:
    record_hash = "evidence-chain-hash-abc123"


class _FakeEvidenceRecorder:
    """Captures the strong-path record_attribution call for assertion."""

    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    def record_attribution(self, **kwargs: Any) -> _FakeEvidenceRecord:
        self.calls.append(kwargs)
        return _FakeEvidenceRecord()


class _FakeDecision:
    def __init__(self, decision_id: uuid.UUID) -> None:
        self.decision_id = decision_id
        self.request_id = "req-1"
        self.policy_version = "policy-v1"


class _FakeDecisionStore:
    def __init__(self, decision_id: uuid.UUID, decision: _FakeDecision) -> None:
        self._d = {decision_id: decision}

    def get(self, key: uuid.UUID) -> _FakeDecision | None:
        return self._d.get(key)


def _decision_backed_symptom(decision_id: str, count: float = 3.0) -> DimensionReading:
    return DimensionReading(
        key="identity",
        kind="gamma",
        observation=(count, 1.0),
        slots={"count": int(count)},
        proof=ProofRef(kind="decision", id=decision_id),
        explained_by=("discovery",),
    )


def _strong_port(
    monkeypatch: Any,
) -> tuple[CausalAttributionPort, _FakeEvidenceRecorder, uuid.UUID, Any]:
    # compute_attribution is imported inside the method at call time, so
    # patching the engine attribute is picked up. We fake it to avoid building
    # a full Decision graph — the mint + evidence-chain seal stay REAL.
    monkeypatch.setattr(
        "tex.causal.attribution_engine.compute_attribution",
        lambda decision: _FakeAttributionResult(),
    )
    decision_id = uuid.uuid4()
    recorder = _FakeEvidenceRecorder()
    signing_key = Ed25519Provider().generate_keypair("vigil-strong-path-test")
    port = CausalAttributionPort(
        decision_store=_FakeDecisionStore(decision_id, _FakeDecision(decision_id)),
        evidence_recorder=recorder,
        signing_key_resolver=lambda: signing_key,
    )
    return port, recorder, decision_id, signing_key


def test_strong_path_seals_via_real_scitt_mint(monkeypatch: Any) -> None:
    port, recorder, decision_id, signing_key = _strong_port(monkeypatch)

    symptom = _decision_backed_symptom(str(decision_id))
    record_hash = port._maybe_seal_decision_attribution(symptom)

    # The strong path ran end-to-end: import resolved, a COSE statement was
    # minted, and the evidence row was recorded. Before the import fix this
    # silently returned None.
    assert record_hash == "evidence-chain-hash-abc123"
    assert len(recorder.calls) == 1

    call = recorder.calls[0]
    assert call["decision_id"] == decision_id
    assert call["attribution_payload"]["primary_root_cause"] == "agent-omega"
    assert call["attribution_payload"]["attribution_method"] == "hcg+counterfactual"
    # A genuine COSE-signed statement was minted via tex.evidence.scitt_statement
    # and handed to the recorder as hex with the matching COSE alg label.
    assert call["signed_statement_cose_alg"] == cose_alg_for(signing_key.algorithm)
    assert bytes.fromhex(call["signed_statement_cose_hex"])  # valid CBOR hex


def test_attribute_tags_evidence_chain_method_on_strong_path(monkeypatch: Any) -> None:
    port, recorder, decision_id, _ = _strong_port(monkeypatch)

    cause = DimensionReading(
        key="discovery",
        kind="gamma",
        observation=(12.0, 1.0),
        slots={"count": 12},
        proof=ProofRef(kind="scan_run", id="s1"),
    )
    symptom = _decision_backed_symptom(str(decision_id), count=3.0)

    out = {r.key: r for r in port.attribute([cause, symptom], tenant="t1")}
    ident = out["identity"]

    assert ident.causal is not None
    # The COSE-signed evidence-chain row sealed, so the public method tag is
    # upgraded. Before the import fix the strong seal returned None and the
    # method stayed "dimension_edge".
    assert ident.causal.method == "dimension_edge+evidence_chain"
    assert recorder.calls  # the strong path actually recorded a row


def test_strong_path_disabled_without_recorder() -> None:
    # Sanity: with no recorder/signing key the strong path is correctly a
    # no-op (None), so the tests above isolate the import, not the wiring.
    port = CausalAttributionPort()
    symptom = _decision_backed_symptom(str(uuid.uuid4()))
    assert port._maybe_seal_decision_attribution(symptom) is None
