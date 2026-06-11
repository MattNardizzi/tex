"""Fail-closed federation gate — earn-it item 5, plus wiring tripwires.

The load-bearing honesty property: with only in-process/self-hosted witnesses,
verification reports ``federated=False`` with the named reason REGARDLESS of
the ``TEX_GIX_WITNESS`` env flag. The flag gates wiring in main.py only;
flipping it must never promote in-tree witnesses to "independent orgs"
(the nanozk discipline: the verifier, not the flag, owns trust).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from tex.interchange.gix import (
    build_checkpoint_publisher,
    get_active_checkpoint_publisher,
)
from tex.interchange.gix_witness import (
    FEDERATED_FALSE_REASON,
    Witness,
    WitnessDescriptor,
    WitnessProvenance,
    gather_cosignatures,
    verify_cosigned_checkpoint,
)
from tex.provenance.ledger import SealedFactLedger

from tests.interchange._helpers import (
    make_witnesses,
    publisher_for,
    seal_decisions,
)

ORIGIN = "orga.example/gix"
SRC_ROOT = Path(__file__).resolve().parents[2] / "src" / "tex"


def _cosigned_world(n_witnesses: int = 3):
    ledger = SealedFactLedger()
    seal_decisions(ledger, 3)
    publisher = publisher_for(ledger, ORIGIN)
    witnesses = make_witnesses(n_witnesses, {ORIGIN: publisher.log_verifier})
    cosigned = gather_cosignatures(
        publisher.build_add_checkpoint_request(0), witnesses
    )
    roster = [w.descriptor for w in witnesses]
    return publisher, witnesses, cosigned, roster


class TestFederatedIsStructurallyFalse:
    @pytest.mark.parametrize("flag", [None, "0", "1", "true", "yes"])
    def test_verification_ignores_the_env_flag(self, monkeypatch, flag):
        """The single most load-bearing test in this file: full quorum,
        valid everything — federated stays False with the named reason, for
        every value of TEX_GIX_WITNESS including enabled ones."""
        if flag is None:
            monkeypatch.delenv("TEX_GIX_WITNESS", raising=False)
        else:
            monkeypatch.setenv("TEX_GIX_WITNESS", flag)
        publisher, _, cosigned, roster = _cosigned_world()
        result = verify_cosigned_checkpoint(
            cosigned,
            log_verifier=publisher.log_verifier,
            roster=roster,
            quorum=3,
        )
        assert result.log_signature_valid
        assert result.quorum_met
        assert len(result.valid_cosigners) == 3
        assert result.federated is False
        assert result.federated_reason == FEDERATED_FALSE_REASON

    def test_external_federated_witness_unconstructible(self):
        with pytest.raises(ValueError, match="independence"):
            Witness(
                "w.example/w",
                trusted_logs={},
                provenance=WitnessProvenance.EXTERNAL_FEDERATED,
            )

    def test_external_federated_descriptor_unconstructible(self):
        with pytest.raises(ValueError, match="independence"):
            WitnessDescriptor(
                name="w.example/w",
                public_key_raw=b"\x00" * 32,
                provenance=WitnessProvenance.EXTERNAL_FEDERATED,
            )


class TestCosignedCheckpointVerification:
    def test_quorum_not_met_with_too_few_cosigners(self):
        publisher, _, cosigned, roster = _cosigned_world(n_witnesses=2)
        result = verify_cosigned_checkpoint(
            cosigned,
            log_verifier=publisher.log_verifier,
            roster=roster,
            quorum=3,
        )
        assert result.log_signature_valid
        assert not result.quorum_met
        assert "2 of the required 3" in result.reason

    def test_tampered_cosignature_not_counted(self):
        publisher, _, cosigned, roster = _cosigned_world()
        from dataclasses import replace

        broken = list(cosigned.cosignature_lines)
        # Flip one base64 character in the signature region of line 0.
        head, b64 = broken[0].rsplit(" ", 1)
        flipped = b64[:-2] + ("A" if b64[-2] != "A" else "B") + b64[-1]
        broken[0] = f"{head} {flipped}"
        tampered = replace(cosigned, cosignature_lines=tuple(broken))
        result = verify_cosigned_checkpoint(
            tampered,
            log_verifier=publisher.log_verifier,
            roster=roster,
            quorum=3,
        )
        assert not result.quorum_met
        assert len(result.valid_cosigners) == 2

    def test_duplicate_cosigner_counted_once(self):
        publisher, _, cosigned, roster = _cosigned_world()
        from dataclasses import replace

        duplicated = replace(
            cosigned,
            cosignature_lines=cosigned.cosignature_lines
            + (cosigned.cosignature_lines[0],),
        )
        result = verify_cosigned_checkpoint(
            duplicated,
            log_verifier=publisher.log_verifier,
            roster=roster,
            quorum=4,
        )
        assert len(result.valid_cosigners) == 3
        assert not result.quorum_met

    def test_wrong_log_key_rejected(self):
        publisher, _, cosigned, roster = _cosigned_world()
        other = publisher_for(SealedFactLedger(), ORIGIN)
        result = verify_cosigned_checkpoint(
            cosigned,
            log_verifier=other.log_verifier,
            roster=roster,
            quorum=3,
        )
        assert not result.log_signature_valid
        assert not result.quorum_met

    def test_invalid_quorum_raises(self):
        publisher, _, cosigned, roster = _cosigned_world()
        with pytest.raises(ValueError):
            verify_cosigned_checkpoint(
                cosigned,
                log_verifier=publisher.log_verifier,
                roster=roster,
                quorum=0,
            )


class TestPublisherSeam:
    """build_checkpoint_publisher is THE main.py line. Inert unless both the
    M0 decision ledger exists AND TEX_GIX_WITNESS is set."""

    def test_flag_unset_returns_none(self, monkeypatch):
        monkeypatch.delenv("TEX_GIX_WITNESS", raising=False)
        ledger = SealedFactLedger()
        assert build_checkpoint_publisher(ledger) is None
        assert get_active_checkpoint_publisher() is None

    def test_none_ledger_returns_none_even_with_flag(self, monkeypatch):
        monkeypatch.setenv("TEX_GIX_WITNESS", "1")
        assert build_checkpoint_publisher(None) is None
        assert get_active_checkpoint_publisher() is None

    def test_flag_and_ledger_build_a_working_publisher(self, monkeypatch):
        monkeypatch.setenv("TEX_GIX_WITNESS", "1")
        monkeypatch.setenv("TEX_GIX_ORIGIN", "orga.example/gix")
        ledger = SealedFactLedger()
        seal_decisions(ledger, 2)
        publisher = build_checkpoint_publisher(ledger)
        try:
            assert publisher is not None
            assert get_active_checkpoint_publisher() is publisher
            snapshot = publisher.current_signed_checkpoint()
            assert snapshot.checkpoint.tree_size == 2
            assert snapshot.checkpoint.origin == "orga.example/gix"
            # Pull-based: appending then re-snapshotting sees the new size.
            seal_decisions(ledger, 1, prefix="late")
            assert publisher.current_signed_checkpoint().checkpoint.tree_size == 3
        finally:
            monkeypatch.delenv("TEX_GIX_WITNESS")
            build_checkpoint_publisher(None)  # clear the registry

    def test_rebuild_with_flag_off_clears_registry(self, monkeypatch):
        monkeypatch.setenv("TEX_GIX_WITNESS", "1")
        ledger = SealedFactLedger()
        assert build_checkpoint_publisher(ledger) is not None
        monkeypatch.delenv("TEX_GIX_WITNESS")
        assert build_checkpoint_publisher(ledger) is None
        assert get_active_checkpoint_publisher() is None


class TestWiringTripwires:
    """Pin the hot-file budget: main.py carries the single seam call; pdp.py
    and provenance/ledger.py carry zero interchange coupling."""

    def test_main_py_has_the_one_seam_call(self):
        source = (SRC_ROOT / "main.py").read_text()
        assert source.count("build_gix_checkpoint_publisher(decision_ledger)") == 1

    def test_pdp_and_ledger_have_zero_interchange_coupling(self):
        for path in ("engine/pdp.py", "provenance/ledger.py"):
            source = (SRC_ROOT / path).read_text()
            assert "interchange" not in source, path
