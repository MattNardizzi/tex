"""
Gate 4 — sequencing and cross-chain independence: the per-request sealed
fact order is pinned (the M0/attempt-hook CONTRACT the L1 binding and L3
counting both depend on), the three chains' pins are INDEPENDENT (a wrong
pin on chain X fails only X's authorship), and ``tree_size`` is never
surfaced as a decision count.
"""

from __future__ import annotations

import dataclasses

from tex.provenance.models import SealedFactKind

from tex.capstone.verify import verify_capstone

A = SealedFactKind.ATTEMPT
D = SealedFactKind.DECISION
E = SealedFactKind.ENFORCEMENT
R = SealedFactKind.DRIFT
ANS = SealedFactKind.ANSWER


def test_epoch_prefix_kind_sequence_is_pinned(capstone_flow) -> None:
    """The marquee prefix, strict on purpose: a new producer appending to
    this flow must show up here and be composed consciously (the twelve-leap
    suite's discipline, extended to the capstone epoch)."""
    records = capstone_flow.materials.ledger.list_all()
    kinds = [r.fact.kind for r in records]
    assert kinds[:13] == [
        A,    # 0  attempt hook (request A — the PQ claim)
        D,    # 1  L10 PQ-durable=false fact (no verdict key)
        D,    # 2  M0 decision A (ABSTAIN + hold)
        E,    # 3  L5 bind (protective pass)
        A,    # 4  attempt hook (reflexive gate evaluation)
        D,    # 5  M0 fact of the reflexive evaluation (PERMIT)
        E,    # 6  L5 denied weakening (ENFORCEMENT, allowed=False)
        A,    # 7  attempt hook (request B — drift breach)
        R,    # 8  L9 DRIFT fact (acted=True)
        D,    # 9  M0 decision B (ABSTAIN)
        E,    # 10 L5 unbind
        A,    # 11 attempt hook (request C — THE capstone decision)
        D,    # 12 M0 decision C (FORBID, structural floor)
    ], "the composed prefix changed — recompose the capstone flow consciously"
    # The final record is the sealed manifest, nothing after it.
    assert kinds[-1] is ANS
    assert sum(1 for k in kinds if k is ANS) == 1


def test_per_request_fact_order_contract(capstone_flow) -> None:
    """Per request: ATTEMPT first; the L10 PQ fact (DECISION kind, NO
    verdict key) sits BETWEEN the attempt and the M0 decision — the
    by-accident contract L1's binding survives on, pinned."""
    materials = capstone_flow.materials
    records = materials.ledger.list_all()
    pq_subject = str(materials.pq_result.decision.request_id)
    pq_kinds = [
        (r.fact.kind, "verdict" in r.fact.detail)
        for r in records
        if r.fact.subject_id == pq_subject
    ]
    assert pq_kinds == [(A, False), (D, False), (D, True)]
    for result in (materials.drift_result, materials.capstone_result):
        subject = str(result.decision.request_id)
        ordered = [
            r.fact.kind for r in records if r.fact.subject_id == subject
        ]
        assert ordered[0] is A and ordered[-1] is D


def test_trial_and_campaign_segments_alternate(capstone_flow) -> None:
    """The L12/L7 segments seal one ATTEMPT+DECISION pair per evaluation —
    nothing else interleaves on the shared chain while they run."""
    records = capstone_flow.materials.ledger.list_all()
    for start, end in (
        capstone_flow.materials.trial_segment,
        capstone_flow.materials.campaign_segment,
    ):
        segment = [r.fact.kind for r in records[start:end]]
        assert len(segment) % 2 == 0 and len(segment) > 0
        assert segment[0::2] == [A] * (len(segment) // 2)
        assert segment[1::2] == [D] * (len(segment) // 2)


def test_three_pins_are_independent(capstone_flow, capstone_pins) -> None:
    """Wrong pin on chain X fails X's authorship (and the manifest's pin
    digest — that is the manifest catching the substitution); the OTHER two
    chains' authorship stays green. Never collapse the three chains."""
    from tex.provenance.ledger import SealedFactLedger
    from tex.voice.attestation import VoiceAttestor

    wrong_pem = SealedFactLedger(key_label="wrong-ledger-key").public_key_pem
    other = VoiceAttestor()
    other.seal(
        transcript="x", routed_dimension=None, verdict="(none)", answer="x",
        object_=None, proof_ref=None, gate={},
    )
    wrong_b64 = other.records()[0].payload["pq_signature"]["public_key_b64"]

    bundle_dir = capstone_flow.bundle_dir

    wrong_ledger = dataclasses.replace(
        capstone_pins, ledger_public_key_pem=wrong_pem
    )
    res = verify_capstone(bundle_dir, wrong_ledger)
    assert not res.check("chain1.authorship_pin").ok
    assert res.check("chain2.authorship_pin").ok
    assert res.check("chain3.authorship_pin").ok
    assert not res.check("pins.digest").ok  # the manifest names the real key
    assert res.check("chain1.integrity").ok  # integrity is pin-independent

    wrong_evidence = dataclasses.replace(
        capstone_pins, evidence_public_key_b64=wrong_b64
    )
    res = verify_capstone(bundle_dir, wrong_evidence)
    assert res.check("chain1.authorship_pin").ok
    assert not res.check("chain2.authorship_pin").ok
    assert res.check("chain3.authorship_pin").ok
    assert res.check("chain2.integrity").ok

    wrong_voice = dataclasses.replace(
        capstone_pins, voice_public_key_b64=wrong_b64
    )
    res = verify_capstone(bundle_dir, wrong_voice)
    assert res.check("chain1.authorship_pin").ok
    assert res.check("chain2.authorship_pin").ok
    assert not res.check("chain3.authorship_pin").ok
    assert res.check("chain3.integrity").ok


def test_tree_size_is_never_a_decision_count(capstone_flow) -> None:
    """The number people will misquote, pinned three ways: the manifest's
    epoch counts disagree with record count, the caveat rides verbatim, and
    the witnessed final checkpoint's tree_size counts EVERY kind."""
    import json

    manifest = capstone_flow.compose.manifest
    records = capstone_flow.materials.ledger.list_all()
    n_decisions = sum(
        1 for r in records if r.fact.kind is SealedFactKind.DECISION
    )
    assert manifest.epoch.decision_kind_fact_count == n_decisions
    assert manifest.epoch.record_count_pre_seal != n_decisions
    final = json.loads(
        (capstone_flow.bundle_dir / "l6_checkpoint_final.json").read_text(
            encoding="utf-8"
        )
    )
    assert final["tree_size"] == len(records)
    assert final["tree_size"] != n_decisions
    assert final["tree_size"] != manifest.epoch.attempt_fact_count
