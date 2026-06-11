"""C2SP tlog-witness add-checkpoint state-machine tests.

Each outcome mirrors the spec's HTTP semantics (re-fetched 2026-06-11):
404 unknown log, 403 untrusted signature, 400 malformed/size-order,
409 conflict (stale old size / equivocation at equal size), 422 bad
consistency proof, 200 cosigned. Every test would fail if the corresponding
refusal stopped firing.
"""

from __future__ import annotations

import base64

from tex.ecosystem._window import empty_root
from tex.interchange.gix import (
    Ed25519NoteSigner,
    build_add_checkpoint_body,
)
from tex.interchange.gix_witness import (
    Witness,
    WitnessOutcome,
)

from tests.interchange._helpers import (
    FIXED_CLOCK,
    publisher_for,
    record_hashes,
    seal_decisions,
)
from tex.provenance.ledger import SealedFactLedger

ORIGIN = "orga.example/gix"


def _world(n_facts: int = 3):
    ledger = SealedFactLedger()
    seal_decisions(ledger, n_facts)
    publisher = publisher_for(ledger, ORIGIN)
    witness = Witness(
        "witness0.example/w",
        trusted_logs={ORIGIN: publisher.log_verifier},
        clock=lambda: FIXED_CLOCK,
    )
    return ledger, publisher, witness


class TestAddCheckpointStateMachine:
    def test_first_observation_cosigns(self):
        _, publisher, witness = _world()
        response = witness.add_checkpoint(publisher.build_add_checkpoint_request(0))
        assert response.outcome is WitnessOutcome.COSIGNED
        assert response.http_analog == 200
        assert response.cosignature_line
        assert witness.latest_size(ORIGIN) == 3

    def test_unknown_origin_404(self):
        _, publisher, _ = _world()
        blind = Witness("w.example/blind", trusted_logs={}, clock=lambda: FIXED_CLOCK)
        response = blind.add_checkpoint(publisher.build_add_checkpoint_request(0))
        assert response.outcome is WitnessOutcome.UNKNOWN_LOG
        assert response.http_analog == 404

    def test_untrusted_log_signature_403(self):
        """A rogue publisher claiming the same origin but holding a different
        key must not be cosigned — the witness pins the log key."""
        ledger, _, witness = _world()
        rogue = publisher_for(ledger, ORIGIN)  # fresh signer, same origin
        response = witness.add_checkpoint(rogue.build_add_checkpoint_request(0))
        assert response.outcome is WitnessOutcome.LOG_UNAUTHENTICATED
        assert response.http_analog == 403

    def test_old_size_above_checkpoint_size_400(self):
        _, publisher, witness = _world()
        snapshot = publisher.current_signed_checkpoint()
        body = build_add_checkpoint_body(5, (), snapshot.signed_note)
        response = witness.add_checkpoint(body)
        assert response.outcome is WitnessOutcome.MALFORMED
        assert response.http_analog == 400

    def test_stale_old_size_409_returns_latest(self):
        ledger, publisher, witness = _world()
        assert witness.add_checkpoint(
            publisher.build_add_checkpoint_request(0)
        ).cosigned
        seal_decisions(ledger, 2, prefix="more")
        # Client claims old size 0 but the witness has already seen size 3.
        response = witness.add_checkpoint(publisher.build_add_checkpoint_request(0))
        assert response.outcome is WitnessOutcome.CONFLICT
        assert response.http_analog == 409
        assert response.latest_size == 3
        # Retrying from the size the conflict reported succeeds.
        assert witness.add_checkpoint(
            publisher.build_add_checkpoint_request(response.latest_size)
        ).cosigned

    def test_honest_extension_cosigns(self):
        ledger, publisher, witness = _world()
        assert witness.add_checkpoint(
            publisher.build_add_checkpoint_request(0)
        ).cosigned
        seal_decisions(ledger, 2, prefix="more")
        response = witness.add_checkpoint(publisher.build_add_checkpoint_request(3))
        assert response.outcome is WitnessOutcome.COSIGNED
        assert witness.latest_size(ORIGIN) == 5

    def test_same_size_recosign_is_idempotent(self):
        _, publisher, witness = _world()
        assert witness.add_checkpoint(
            publisher.build_add_checkpoint_request(0)
        ).cosigned
        response = witness.add_checkpoint(publisher.build_add_checkpoint_request(3))
        assert response.outcome is WitnessOutcome.COSIGNED
        assert witness.latest_size(ORIGIN) == 3

    def test_same_size_different_root_409_equivocation(self):
        _, publisher, witness = _world()
        assert witness.add_checkpoint(
            publisher.build_add_checkpoint_request(0)
        ).cosigned
        # Same origin, same signer, same size, different leaves: equivocation.
        forked = publisher_for_fork(publisher, record_hashes(3, salt="fork"))
        response = witness.add_checkpoint(forked.build_add_checkpoint_request(3))
        assert response.outcome is WitnessOutcome.CONFLICT
        assert response.http_analog == 409

    def test_same_size_with_proof_422(self):
        _, publisher, witness = _world()
        assert witness.add_checkpoint(
            publisher.build_add_checkpoint_request(0)
        ).cosigned
        snapshot = publisher.current_signed_checkpoint()
        body = build_add_checkpoint_body(
            3, (record_hashes(1, salt="x")[0],), snapshot.signed_note
        )
        response = witness.add_checkpoint(body)
        assert response.outcome is WitnessOutcome.BAD_CONSISTENCY_PROOF

    def test_bad_consistency_proof_422(self):
        ledger, publisher, witness = _world()
        assert witness.add_checkpoint(
            publisher.build_add_checkpoint_request(0)
        ).cosigned
        seal_decisions(ledger, 2, prefix="more")
        snapshot = publisher.current_signed_checkpoint()
        bogus_proof = tuple(record_hashes(2, salt="bogus"))
        body = build_add_checkpoint_body(3, bogus_proof, snapshot.signed_note)
        response = witness.add_checkpoint(body)
        assert response.outcome is WitnessOutcome.BAD_CONSISTENCY_PROOF
        assert response.http_analog == 422
        # The refused submission must not advance witness state.
        assert witness.latest_size(ORIGIN) == 3

    def test_proof_from_size_zero_refused(self):
        _, publisher, witness = _world()
        snapshot = publisher.current_signed_checkpoint()
        body = build_add_checkpoint_body(
            0, (record_hashes(1, salt="x")[0],), snapshot.signed_note
        )
        response = witness.add_checkpoint(body)
        assert response.outcome is WitnessOutcome.BAD_CONSISTENCY_PROOF

    def test_more_than_63_proof_lines_400(self):
        _, publisher, witness = _world()
        snapshot = publisher.current_signed_checkpoint()
        lines = ["old 1"]
        lines.extend(
            base64.b64encode(bytes.fromhex(h)).decode()
            for h in record_hashes(64, salt="big")
        )
        body = "\n".join(lines) + "\n\n" + snapshot.signed_note
        response = witness.add_checkpoint(body)
        assert response.outcome is WitnessOutcome.MALFORMED

    def test_malformed_old_lines_400(self):
        _, publisher, witness = _world()
        note = publisher.current_signed_checkpoint().signed_note
        for bad in ("old 03", "olde 3", "old", "old x", "3"):
            response = witness.add_checkpoint(f"{bad}\n\n{note}")
            assert response.outcome is WitnessOutcome.MALFORMED, bad

    def test_missing_separator_400(self):
        _, publisher, witness = _world()
        note = publisher.current_signed_checkpoint().signed_note
        response = witness.add_checkpoint("old 0\n" + note.split("\n")[0])
        assert response.outcome is WitnessOutcome.MALFORMED

    def test_empty_tree_checkpoint(self):
        ledger = SealedFactLedger()
        publisher = publisher_for(ledger, ORIGIN)
        witness = Witness(
            "witness0.example/w",
            trusted_logs={ORIGIN: publisher.log_verifier},
            clock=lambda: FIXED_CLOCK,
        )
        response = witness.add_checkpoint(publisher.build_add_checkpoint_request(0))
        assert response.cosigned
        # And the empty root is pinned: a size-0 checkpoint with a junk root
        # is refused.
        signer = Ed25519NoteSigner("junk.example/gix")
        junk_witness = Witness(
            "witness1.example/w",
            trusted_logs={"junk.example/gix": signer.verifier},
            clock=lambda: FIXED_CLOCK,
        )
        junk_root_b64 = base64.b64encode(b"\x11" * 32).decode()
        junk_note = signer.sign_note(f"junk.example/gix\n0\n{junk_root_b64}\n")
        refused = junk_witness.add_checkpoint(f"old 0\n\n{junk_note}")
        assert refused.outcome is WitnessOutcome.BAD_CONSISTENCY_PROOF
        assert empty_root() != (b"\x11" * 32).hex()

    def test_refusals_never_regress_state(self):
        """Monotonicity: once at size 5, no refused submission moves the
        witness backwards or forwards."""
        ledger, publisher, witness = _world()
        witness.add_checkpoint(publisher.build_add_checkpoint_request(0))
        seal_decisions(ledger, 2, prefix="more")
        witness.add_checkpoint(publisher.build_add_checkpoint_request(3))
        assert witness.latest_size(ORIGIN) == 5
        witness.add_checkpoint(publisher.build_add_checkpoint_request(3))
        assert witness.latest_size(ORIGIN) == 5


def publisher_for_fork(publisher, forked_hashes):
    """Same origin, SAME log signer, different leaves — the equivocation
    scenario where the log operator itself signs two diverging views."""
    from tex.interchange.gix import CheckpointPublisher

    return CheckpointPublisher(
        origin=publisher.origin,
        read_record_hashes=lambda: tuple(forked_hashes),
        signer=publisher._signer,  # noqa: SLF001 — deliberate: same identity
    )
