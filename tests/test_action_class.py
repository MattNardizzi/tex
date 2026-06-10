"""
Tests for the action-class reversibility × blast-radius floor
(contracts/action_class.py) — Wave 2 leap L4.

Two things are under scrutiny:
  1. the FIXED lattice classifier — enum order, worst-step join, the exhaustive
     4×4 cell map, and fail-closed coercion of unparseable declarations;
  2. the under-classification certificate — that it is inert without a corpus,
     computes the *reused* Hoeffding-Bentkus bound, stays uncertified on a
     SYNTHETIC corpus, and that the synthetic corpus is genuinely non-circular.
"""

from __future__ import annotations

import pytest

from tex.contracts.action_class import (
    ACTION_CLASS_CERT,
    ACTION_CLASS_CODE,
    CELL_MAP_VERSION,
    ActionClass,
    ActionClassCase,
    BlastRadius,
    Reversibility,
    NEUTRAL_ACTION_CLASS,
    build_action_class_corpus,
    certify_action_class,
    classify_action_class,
    classify_action_class_block,
    evaluate_action_class,
)
from tex.engine.crc_gate import hoeffding_bentkus_ucb

from tests.factories import make_request


# ── axes: order, thresholds, join ───────────────────────────────────────


def test_unknown_is_the_top_of_each_axis() -> None:
    assert max(Reversibility) is Reversibility.UNKNOWN
    assert max(BlastRadius) is BlastRadius.UNKNOWN
    # monotone verdict class: more conservative = higher
    assert ActionClass.NEUTRAL < ActionClass.ABSTAIN < ActionClass.FORBID


def test_is_irreversible_threshold() -> None:
    assert Reversibility.IRREVERSIBLE.is_irreversible
    assert Reversibility.UNKNOWN.is_irreversible
    assert not Reversibility.RECOVERABLE.is_irreversible
    assert not Reversibility.REVERSIBLE.is_irreversible


def test_is_public_threshold() -> None:
    assert BlastRadius.PUBLIC.is_public
    assert BlastRadius.UNKNOWN.is_public
    assert not BlastRadius.TENANT.is_public
    assert not BlastRadius.SELF.is_public


def test_join_is_worst_step_max() -> None:
    assert Reversibility.REVERSIBLE.join(Reversibility.IRREVERSIBLE) is Reversibility.IRREVERSIBLE
    assert Reversibility.RECOVERABLE.join(Reversibility.UNKNOWN) is Reversibility.UNKNOWN
    assert BlastRadius.SELF.join(BlastRadius.PUBLIC) is BlastRadius.PUBLIC
    assert BlastRadius.TENANT.join(BlastRadius.SELF) is BlastRadius.TENANT


# ── the FIXED cell map (exhaustive) ─────────────────────────────────────


def test_cell_map_exhaustive() -> None:
    """FORBID exactly on the irreversible-or-worse × public-or-worse corner."""
    for rev in Reversibility:
        for blast in BlastRadius:
            cell = classify_action_class(rev, blast)
            if rev.is_irreversible and blast.is_public:
                assert cell is ActionClass.FORBID, (rev, blast)
            elif rev.is_irreversible or blast.is_public:
                assert cell is ActionClass.ABSTAIN, (rev, blast)
            else:
                assert cell is ActionClass.NEUTRAL, (rev, blast)


def test_named_forbid_cell() -> None:
    assert classify_action_class(Reversibility.IRREVERSIBLE, BlastRadius.PUBLIC) is ActionClass.FORBID


def test_unknown_corners_fail_closed_to_forbid() -> None:
    # An uncharacterised axis is swept into the dangerous tier.
    assert classify_action_class(Reversibility.UNKNOWN, BlastRadius.PUBLIC) is ActionClass.FORBID
    assert classify_action_class(Reversibility.IRREVERSIBLE, BlastRadius.UNKNOWN) is ActionClass.FORBID
    assert classify_action_class(Reversibility.UNKNOWN, BlastRadius.UNKNOWN) is ActionClass.FORBID


def test_cell_map_version_is_stable_hash() -> None:
    assert isinstance(CELL_MAP_VERSION, str) and len(CELL_MAP_VERSION) == 12


# ── block classifier: join over steps, fail-closed coercion ─────────────


def test_block_worst_step_join_forbids() -> None:
    # A benign step + one irreversible×public step → worst-step join FORBIDs.
    out = classify_action_class_block(
        {
            "steps": [
                {"reversibility": "REVERSIBLE", "blast_radius": "SELF"},
                {"reversibility": "IRREVERSIBLE", "blast_radius": "PUBLIC"},
                {"reversibility": "RECOVERABLE", "blast_radius": "TENANT"},
            ]
        }
    )
    assert out.fired is True
    assert out.action_class is ActionClass.FORBID
    assert out.worst_reversibility is Reversibility.IRREVERSIBLE
    assert out.worst_blast is BlastRadius.PUBLIC
    assert out.n_steps == 3
    assert out.code == ACTION_CLASS_CODE


def test_block_abstain_cell_is_not_fired() -> None:
    # One axis hot (irreversible × tenant) → ABSTAIN cell, recorded, NOT fired.
    out = classify_action_class_block(
        {"steps": [{"reversibility": "IRREVERSIBLE", "blast_radius": "TENANT"}]}
    )
    assert out.action_class is ActionClass.ABSTAIN
    assert out.fired is False
    assert out.is_hold is True


def test_block_safe_cell_is_neutral_noop() -> None:
    out = classify_action_class_block(
        {"steps": [{"reversibility": "REVERSIBLE", "blast_radius": "SELF"}]}
    )
    assert out.action_class is ActionClass.NEUTRAL
    assert out.fired is False


def test_unparseable_axis_is_unknown_failclosed() -> None:
    # A present step with a garbage reversibility → UNKNOWN; with a public blast
    # that lands in the FORBID corner (fail-closed, never silently REVERSIBLE).
    out = classify_action_class_block(
        {"steps": [{"reversibility": "frobnicate", "blast_radius": "PUBLIC"}]}
    )
    assert out.worst_reversibility is Reversibility.UNKNOWN
    assert out.fired is True


def test_missing_axis_is_unknown_failclosed() -> None:
    # A step that omits blast_radius → blast UNKNOWN (uncharacterised = dangerous).
    out = classify_action_class_block(
        {"steps": [{"reversibility": "IRREVERSIBLE"}]}
    )
    assert out.worst_blast is BlastRadius.UNKNOWN
    assert out.fired is True


def test_empty_declaration_is_neutral_not_forbid() -> None:
    # A present-but-empty declaration must never fabricate a FORBID.
    assert classify_action_class_block({"steps": []}).action_class is ActionClass.NEUTRAL
    assert classify_action_class_block({}).action_class is ActionClass.NEUTRAL
    assert classify_action_class_block({"steps": "nope"}).action_class is ActionClass.NEUTRAL
    # Non-Mapping step entries are skipped; all-skipped → NEUTRAL no-op.
    assert classify_action_class_block({"steps": ["x", 3]}).action_class is ActionClass.NEUTRAL


# ── opt-in evaluate(request): no-op + NO envelope cross-read ─────────────


def test_evaluate_noop_when_metadata_absent() -> None:
    out = evaluate_action_class(make_request())
    assert out is NEUTRAL_ACTION_CLASS
    assert out.fired is False


def test_evaluate_does_not_read_request_envelope() -> None:
    # The default request has an EXTERNAL recipient + email channel but NO
    # action_class metadata. The contract must NOT derive blast from the
    # envelope — it stays a no-op. (Guards the deleted envelope cross-check.)
    req = make_request(recipient="someone@external.example.com", channel="email")
    assert evaluate_action_class(req).fired is False


def test_evaluate_forbids_on_declared_block() -> None:
    req = make_request(
        metadata={"action_class": {"steps": [{"reversibility": "IRREVERSIBLE", "blast_radius": "PUBLIC"}]}}
    )
    out = evaluate_action_class(req)
    assert out.fired is True
    assert out.action_class is ActionClass.FORBID


# ── certificate: inert, reused bound, field-only certification ──────────


def test_shipped_default_cert_is_inert() -> None:
    cert = ACTION_CLASS_CERT
    assert cert.enabled is False
    assert cert.certified is False
    assert cert.corpus_kind == "none"
    assert cert.under_risk_upper_bound == 1.0
    assert cert.certified_under_classification_rate == 1.0
    assert cert.n_calibration == 0
    assert cert.cell_map_version == CELL_MAP_VERSION


def test_cert_empty_corpus_is_inert() -> None:
    assert certify_action_class([]).certified is False
    assert certify_action_class([]).enabled is False


def test_cert_reuses_hoeffding_bentkus_exactly() -> None:
    # Two known misses out of four → r_hat = 0.5; the cert's UCB must equal the
    # reused crc_gate function exactly (no reimplementation drift).
    cases = [
        ActionClassCase(declared_steps=(("RECOVERABLE", "TENANT"),), ground_truth_must_forbid=True),  # miss
        ActionClassCase(declared_steps=(("RECOVERABLE", "TENANT"),), ground_truth_must_forbid=True),  # miss
        ActionClassCase(declared_steps=(("IRREVERSIBLE", "PUBLIC"),), ground_truth_must_forbid=True),  # hit
        ActionClassCase(declared_steps=(("REVERSIBLE", "SELF"),), ground_truth_must_forbid=False),     # tn
    ]
    cert = certify_action_class(cases, alpha=0.05, delta=0.05, corpus_kind="field")
    assert cert.empirical_under_classification_rate == 0.5
    assert cert.under_risk_upper_bound == round(hoeffding_bentkus_ucb(0.5, 4, 0.05), 6)


def test_cert_certifies_only_with_field_corpus() -> None:
    # The gating predicate: a clean (0-miss) corpus has UCB <= alpha, but only a
    # 'field' corpus is allowed to read certified=True. The SAME data labeled
    # 'synthetic' must stay certified=False (the honesty gate).
    clean = [
        ActionClassCase(declared_steps=(("IRREVERSIBLE", "PUBLIC"),), ground_truth_must_forbid=True)
        for _ in range(120)
    ] + [
        ActionClassCase(declared_steps=(("REVERSIBLE", "SELF"),), ground_truth_must_forbid=False)
        for _ in range(120)
    ]
    field = certify_action_class(clean, alpha=0.05, delta=0.05, corpus_kind="field")
    synth = certify_action_class(clean, alpha=0.05, delta=0.05, corpus_kind="synthetic")
    assert field.empirical_under_classification_rate == 0.0
    assert field.under_risk_upper_bound <= 0.05
    assert field.certified is True
    assert field.certified_under_classification_rate == field.under_risk_upper_bound
    # identical data + numbers, but synthetic never claims a field guarantee
    assert synth.under_risk_upper_bound == field.under_risk_upper_bound
    assert synth.certified is False
    assert synth.certified_under_classification_rate == 1.0


def test_circular_corpus_would_falsely_certify() -> None:
    """Documents WHY the corpus tripwire exists: a 0-miss corpus certifies at
    ~0.0198 <= 0.05. If ground truth were derived from the declared bits, misses
    would be 0 by construction and that bound would be a fabricated guarantee."""
    assert hoeffding_bentkus_ucb(0.0, 200, 0.05) <= 0.05


# ── the synthetic corpus is genuinely non-circular ──────────────────────


def test_corpus_builds_and_is_non_circular() -> None:
    cal, test = build_action_class_corpus()
    assert len(cal) == 300
    assert len(test) == 200
    # Genuine under-classification events exist (declared under-states the truth),
    # so the bounded rate is non-zero — not the circular 0.
    test_misses = sum(1 for c in test if c.is_under_classification)
    assert test_misses >= 20
    # Every under-classification is a real disagreement: ground truth says
    # must-FORBID, but the lattice (reading declared features) does not forbid.
    for c in test:
        if c.is_under_classification:
            assert c.ground_truth_must_forbid is True
            assert c.predicted() is not ActionClass.FORBID


def test_corpus_cert_is_synthetic_uncertified_nonzero() -> None:
    cal, test = build_action_class_corpus()
    cert = certify_action_class(cal, holdout=test, corpus_kind="synthetic")
    assert cert.corpus_kind == "synthetic"
    assert cert.certified is False  # synthetic never certifies (research-early)
    assert cert.empirical_under_classification_rate > 0.0  # genuine, non-circular
    assert cert.under_risk_upper_bound == round(
        hoeffding_bentkus_ucb(cert.empirical_under_classification_rate, 300, 0.05), 6
    )
    assert cert.n_test == 200
    assert cert.holdout_within_bound is True


def test_corpus_is_deterministic() -> None:
    cal1, test1 = build_action_class_corpus(seed=1729)
    cal2, test2 = build_action_class_corpus(seed=1729)
    assert [c.declared_steps for c in cal1] == [c.declared_steps for c in cal2]
    assert [c.ground_truth_must_forbid for c in test1] == [c.ground_truth_must_forbid for c in test2]


def test_corpus_tripwire_raises_on_circular_model() -> None:
    # p_under=0 means declared == true everywhere → zero under-classification →
    # the anti-circularity assertion must fire rather than ship a vacuous bound.
    with pytest.raises(AssertionError):
        build_action_class_corpus(p_under=0.0)
