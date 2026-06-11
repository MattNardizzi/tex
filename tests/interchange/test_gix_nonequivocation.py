"""Non-equivocation headline tests — earn-it items 1 and 3.

ROADMAP.md L6 "Earns it by": ≥3 witnesses refuse to cosign a forked/rewritten
checkpoint; the honest extension cosigns fine. Plus the restart-fork honesty
test: the in-memory ledger restarts as a fresh chain, witnesses treat it as a
fork and refuse — checkpoint continuity across restarts is NOT claimed.
"""

from __future__ import annotations

import hashlib

from tex.interchange.gix import CheckpointPublisher
from tex.interchange.gix_witness import (
    WitnessOutcome,
    gather_cosignatures,
)
from tex.provenance.ledger import SealedFactLedger

from tests.interchange._helpers import (
    FIXED_CLOCK,
    make_witnesses,
    publisher_for,
    seal_decisions,
)

ORIGIN = "orga.example/gix"
N_WITNESSES = 4  # claim is ">= 3 witnesses refuse"; run one more than the bar


def _world():
    ledger = SealedFactLedger()
    seal_decisions(ledger, 3)
    publisher = publisher_for(ledger, ORIGIN)
    witnesses = make_witnesses(
        N_WITNESSES, {ORIGIN: publisher.log_verifier}
    )
    return ledger, publisher, witnesses


def _fork_of(publisher, hashes):
    """Same origin, SAME log signer (the operator signs both views), forked
    leaves — the equivocation under test."""
    return CheckpointPublisher(
        origin=publisher.origin,
        read_record_hashes=lambda: tuple(hashes),
        signer=publisher._signer,  # noqa: SLF001 — deliberate equivocation
    )


class TestNonEquivocationHeadline:
    def test_forked_checkpoint_refused_by_at_least_three_witnesses(self):
        ledger, publisher, witnesses = _world()

        # 1. Checkpoint the honest log at size 3; all witnesses cosign.
        first = gather_cosignatures(
            publisher.build_add_checkpoint_request(0), witnesses
        )
        assert len(first.cosignature_lines) == N_WITNESSES
        assert first.refusal_count == 0

        # 2. Honest extension to size 5: all witnesses cosign fine.
        seal_decisions(ledger, 2, prefix="more")
        honest = gather_cosignatures(
            publisher.build_add_checkpoint_request(3), witnesses
        )
        assert len(honest.cosignature_lines) == N_WITNESSES
        assert honest.refusal_count == 0

        # 3. Fork: rewrite an already-witnessed leaf and extend to size 6.
        #    The log operator signs the forked view with its real key — only
        #    the witnesses' consistency check stands in the way.
        forked_hashes = [r.record_hash for r in ledger.list_all()]
        forked_hashes[1] = hashlib.sha256(b"rewritten history").hexdigest()
        forked_hashes.append(hashlib.sha256(b"fork growth").hexdigest())
        fork = _fork_of(publisher, forked_hashes)

        refused = gather_cosignatures(
            fork.build_add_checkpoint_request(5), witnesses
        )
        assert refused.cosignature_lines == ()
        assert refused.refusal_count >= 3  # the ROADMAP bar
        assert refused.refusal_count == N_WITNESSES
        for _, response in refused.refusals:
            assert response.outcome is WitnessOutcome.BAD_CONSISTENCY_PROOF

        # 4. Same-size rewrite (no growth): refused as CONFLICT, the
        #    equivocation analog of two roots at one size.
        same_size_fork = _fork_of(publisher, forked_hashes[:5])
        refused_same = gather_cosignatures(
            same_size_fork.build_add_checkpoint_request(5), witnesses
        )
        assert refused_same.cosignature_lines == ()
        assert refused_same.refusal_count >= 3
        for _, response in refused_same.refusals:
            assert response.outcome is WitnessOutcome.CONFLICT

        # 5. The refusals must not have poisoned honest progress.
        seal_decisions(ledger, 1, prefix="after")
        recovered = gather_cosignatures(
            publisher.build_add_checkpoint_request(5), witnesses
        )
        assert len(recovered.cosignature_lines) == N_WITNESSES

    def test_fresh_witness_cannot_detect_a_fork_it_never_observed(self):
        """Honest trust-model boundary: non-equivocation comes from witness
        STATE, not magic. A brand-new witness that never saw the honest log
        will cosign a fork presented from size 0 — which is exactly why the
        claim requires witnesses with continuous observation, and why
        organizational independence (who runs the witnesses) is a separate,
        unclaimed property."""
        ledger, publisher, _ = _world()
        forked_hashes = [r.record_hash for r in ledger.list_all()]
        forked_hashes[1] = hashlib.sha256(b"rewritten history").hexdigest()
        fork = _fork_of(publisher, forked_hashes)

        naive = make_witnesses(1, {ORIGIN: publisher.log_verifier})
        result = gather_cosignatures(
            fork.build_add_checkpoint_request(0), naive
        )
        assert len(result.cosignature_lines) == 1  # it cannot know better


class TestRestartForkHonesty:
    """The decision ledger is in-memory (TEX_SEAL_DECISIONS opt-in): a process
    restart starts a fresh chain. Witnesses MUST treat that as a fork.
    Checkpoint continuity across restarts is NOT claimed — an operator must
    either persist witness/log state or start a new origin."""

    def test_restart_with_old_size_zero_conflicts(self):
        ledger, publisher, witnesses = _world()
        gather_cosignatures(publisher.build_add_checkpoint_request(0), witnesses)

        # "Restart": fresh in-memory ledger, same origin, same log key (the
        # org reloads its persisted signing key but the chain restarts).
        restarted = SealedFactLedger()
        seal_decisions(restarted, 2, prefix="post-restart")
        restart_pub = CheckpointPublisher(
            origin=ORIGIN,
            read_record_hashes=lambda: tuple(
                r.record_hash for r in restarted.list_all()
            ),
            signer=publisher._signer,  # noqa: SLF001
        )
        result = gather_cosignatures(
            restart_pub.build_add_checkpoint_request(0), witnesses
        )
        assert result.cosignature_lines == ()
        assert result.refusal_count >= 3
        for _, response in result.refusals:
            assert response.outcome is WitnessOutcome.CONFLICT
            assert response.latest_size == 3

    def test_restart_claiming_continuity_fails_the_proof(self):
        """A restarted log that lies about continuity (claims old size 3 over
        its fresh chain) cannot produce a verifying consistency proof."""
        ledger, publisher, witnesses = _world()
        gather_cosignatures(publisher.build_add_checkpoint_request(0), witnesses)

        restarted = SealedFactLedger()
        seal_decisions(restarted, 7, prefix="post-restart")
        restart_pub = CheckpointPublisher(
            origin=ORIGIN,
            read_record_hashes=lambda: tuple(
                r.record_hash for r in restarted.list_all()
            ),
            signer=publisher._signer,  # noqa: SLF001
        )
        result = gather_cosignatures(
            restart_pub.build_add_checkpoint_request(3), witnesses
        )
        assert result.cosignature_lines == ()
        assert result.refusal_count >= 3
        for _, response in result.refusals:
            assert response.outcome is WitnessOutcome.BAD_CONSISTENCY_PROOF
