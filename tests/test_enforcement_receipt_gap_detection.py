"""
Negative-space enforcement receipts — a MISSING receipt is a detectable bypass.

The hash chain proves the receipts that ARE present are unaltered and Tex-authored.
What it cannot prove is that the set is COMPLETE: an action that bypassed the gate
leaves no record to tamper with, so a chain of the survivors verifies cleanly. The
per-identity sequence closes that hole — each identity's receipts must be contiguous
from 0, so a gap is a missing receipt (a deleted record, or, when the sequence is the
actor's attested monotonic counter, an action that was never adjudicated).

These tests prove the property end to end, including the case that is the whole point:
a bundle whose signatures and chain VERIFY while the gap check still flags a bypass.
"""

from __future__ import annotations

import pytest

from tex.domain.evidence import EvidenceMaturity
from tex.provenance.ledger import SealedFactLedger
from tex.provenance.models import SealedFact, SealedFactKind
from tex.verifier.check import verify_bundle, verify_no_identity_gaps
from tex.verifier.export import portable_bundle_from_ledger


def _enf(subject: str, *, allowed: bool = False, outcome: str = "blocked") -> SealedFact:
    """A minimal ENFORCEMENT fact — the per-identity sequence is folded in by the
    ledger's ``append_sequenced``, not here."""
    return SealedFact(
        kind=SealedFactKind.ENFORCEMENT,
        subject_id=subject,
        claim=f"gate {outcome} action for {subject}",
        maturity=EvidenceMaturity.RESEARCH_SOLID,
        detail={"allowed": allowed, "outcome": outcome},
    )


def test_ledger_assigned_sequence_is_contiguous_and_clean() -> None:
    led = SealedFactLedger()
    for i in range(3):
        led.append_sequenced(_enf(f"a-{i}"), identity_key="declared:agent-A")
    for i in range(2):
        led.append_sequenced(_enf(f"b-{i}"), identity_key="declared:agent-B")

    rep = led.verify_no_gaps()
    assert rep["complete"] is True
    assert rep["identities"] == 2
    assert rep["sequenced_records"] == 5

    # The sequence is sealed INTO the fact, so it is signed and chain-bound.
    seqs_a = [r.fact.detail["identity_seq"] for r in led.list_for_identity("declared:agent-A")]
    assert seqs_a == [0, 1, 2]
    assert led.verify_chain()["intact"] is True
    assert led.verify_signatures()["valid"] is True


def test_actor_counter_skip_is_detected_as_bypass() -> None:
    led = SealedFactLedger()
    # The actor's attested monotonic counter jumps 1 -> 3: action 2 never reached
    # the gate. Nothing was deleted; a receipt was simply never created.
    for s in (0, 1, 3):
        led.append_sequenced(
            _enf(f"req-{s}"), identity_key="attested:acme:agent-7", claimed_seq=s
        )

    rep = led.verify_no_gaps()
    assert rep["complete"] is False
    assert rep["gaps"] == {"attested:acme:agent-7": [2]}

    # The crux: the records that exist are a perfectly valid, untampered, signed
    # chain. Integrity is intact; completeness is not. Only the gap check sees it.
    assert led.verify_chain()["intact"] is True
    assert led.verify_signatures()["valid"] is True


def test_duplicate_sequence_is_flagged() -> None:
    led = SealedFactLedger()
    for s in (0, 1, 1):  # a replayed counter value
        led.append_sequenced(_enf("r"), identity_key="k", claimed_seq=s)
    rep = led.verify_no_gaps()
    assert rep["complete"] is False
    assert rep["duplicates"] == {"k": [1]}


def test_interior_deletion_breaks_the_chain() -> None:
    led = SealedFactLedger()
    for i in range(4):
        led.append_sequenced(_enf(f"r{i}"), identity_key="k")
    # Excising an interior sealed record severs the hash linkage (a complement to
    # the gap check: deletion of a present record is caught by the chain itself).
    del led._entries[1]
    assert led.verify_chain()["intact"] is False


def test_offline_bundle_detects_bypass_that_signatures_and_chain_pass() -> None:
    led = SealedFactLedger()
    for s in (0, 1, 3):  # action 2 bypassed the gate
        led.append_sequenced(
            _enf(f"r{s}"), identity_key="attested:acme:agent-7", claimed_seq=s
        )
    bundle = portable_bundle_from_ledger(led, export_name="gap-test")

    # A standalone verifier holding only the bundle + the pinned key: the bundle
    # is VALID — chain replays, every signature verifies against Tex's key.
    report = verify_bundle(bundle, pinned_public_key_pem=led.public_key_pem)
    assert report.is_valid is True

    # ...and yet, from the same bundle alone, the negative-space check proves a
    # receipt is missing. This is the property no signature/chain check can make.
    gaps = verify_no_identity_gaps(bundle)
    assert gaps.complete is False
    assert gaps.gaps == (("attested:acme:agent-7", (2,)),)
    assert gaps.sequenced_records == 3


def test_clean_bundle_has_no_gaps() -> None:
    led = SealedFactLedger()
    for s in range(4):
        led.append_sequenced(_enf(f"r{s}"), identity_key="k", claimed_seq=s)
    bundle = portable_bundle_from_ledger(led, export_name="clean")
    assert verify_no_identity_gaps(bundle).complete is True


def test_unparseable_bundle_is_not_complete() -> None:
    # Fail-closed: a bundle that proves nothing is never "complete".
    rep = verify_no_identity_gaps("this is not json")
    assert rep.complete is False
    assert rep.sequenced_records == 0


def test_live_gate_emits_sequenced_receipts() -> None:
    """The LIVE proof-carrying gate (not a library call) seals per-identity
    sequenced receipts for every blocked action."""
    from tex.enforcement.errors import TexForbiddenError
    from tex.enforcement.seal import build_proof_carrying_gate
    from tex.governance.standing import StandingGovernance

    class _EmptyRegistry:
        def get(self, _uid):
            return None

        def list_all(self):
            return []

    ledger = SealedFactLedger()
    gov = StandingGovernance(agent_registry=_EmptyRegistry())
    gate, _obs = build_proof_carrying_gate(gov, ledger=ledger, tenant="acme")
    guarded = gate.wrap(
        lambda *, content: None, content_arg="content", action_type="rm_rf"
    )

    for _ in range(2):
        with pytest.raises(TexForbiddenError):
            guarded(content="rm -rf / --no-preserve-root")

    recs = ledger.list_by_kind(SealedFactKind.ENFORCEMENT)
    assert len(recs) == 2
    for r in recs:
        assert "identity_key" in r.fact.detail
        assert isinstance(r.fact.detail["identity_seq"], int)
    assert sorted(r.fact.detail["identity_seq"] for r in recs) == [0, 1]
    assert ledger.verify_no_gaps()["complete"] is True
    assert ledger.verify_chain()["intact"] is True
