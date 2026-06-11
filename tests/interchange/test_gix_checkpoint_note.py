"""C2SP wire-format tests: tlog-checkpoint note body, signed-note signatures,
and cosignature/v1 byte layout (specs re-fetched 2026-06-11).

The cosignature test re-derives the signed message and key ID by hand from
the spec text, independent of the implementation under test.
"""

from __future__ import annotations

import base64
import hashlib

import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519

from tex.ecosystem._window import merkle_root
from tex.interchange.gix import (
    Checkpoint,
    Ed25519NoteSigner,
    Ed25519NoteVerifier,
    split_signed_note,
    verify_note,
)
from tex.interchange.gix_witness import (
    Witness,
    verify_cosignature_line,
)

from tests.interchange._helpers import FIXED_CLOCK, record_hashes


def _checkpoint(origin: str = "orga.example/gix", n: int = 5) -> Checkpoint:
    root = bytes.fromhex(merkle_root(record_hashes(n)))
    return Checkpoint(origin=origin, tree_size=n, root_hash=root)


class TestCheckpointNoteBody:
    def test_roundtrip(self):
        cp = _checkpoint()
        parsed = Checkpoint.parse(cp.note_text())
        assert parsed == cp

    def test_extension_lines_roundtrip(self):
        cp = Checkpoint(
            origin="orga.example/gix",
            tree_size=3,
            root_hash=bytes.fromhex(merkle_root(record_hashes(3))),
            extension_lines=("opaque extension", "another"),
        )
        assert Checkpoint.parse(cp.note_text()) == cp

    def test_note_text_format_is_exact(self):
        cp = _checkpoint(n=5)
        lines = cp.note_text().split("\n")
        assert lines[0] == "orga.example/gix"
        assert lines[1] == "5"
        assert base64.b64decode(lines[2]) == cp.root_hash
        assert lines[3] == ""  # trailing newline

    def test_leading_zero_size_rejected(self):
        text = "orga.example/gix\n07\n" + base64.b64encode(b"\x00" * 32).decode() + "\n"
        with pytest.raises(ValueError):
            Checkpoint.parse(text)

    def test_non_decimal_size_rejected(self):
        text = "orga.example/gix\n-1\n" + base64.b64encode(b"\x00" * 32).decode() + "\n"
        with pytest.raises(ValueError):
            Checkpoint.parse(text)

    def test_zero_size_allowed(self):
        text = "orga.example/gix\n0\n" + base64.b64encode(b"\x00" * 32).decode() + "\n"
        assert Checkpoint.parse(text).tree_size == 0

    def test_short_root_rejected(self):
        text = "orga.example/gix\n5\n" + base64.b64encode(b"\x00" * 16).decode() + "\n"
        with pytest.raises(ValueError):
            Checkpoint.parse(text)

    def test_bad_base64_root_rejected(self):
        with pytest.raises(ValueError):
            Checkpoint.parse("orga.example/gix\n5\nnot/base64!!\n")

    def test_missing_lines_rejected(self):
        with pytest.raises(ValueError):
            Checkpoint.parse("orga.example/gix\n5\n")

    def test_missing_trailing_newline_rejected(self):
        cp = _checkpoint()
        with pytest.raises(ValueError):
            Checkpoint.parse(cp.note_text()[:-1])

    def test_control_chars_rejected(self):
        with pytest.raises(ValueError):
            Checkpoint(
                origin="bad\torigin",
                tree_size=1,
                root_hash=b"\x00" * 32,
            )


class TestSignedNote:
    def test_sign_and_verify(self):
        signer = Ed25519NoteSigner("orga.example/gix")
        signed = signer.sign_note(_checkpoint().note_text())
        assert verify_note(signed, [signer.verifier]) == ("orga.example/gix",)

    def test_split_signed_note(self):
        signer = Ed25519NoteSigner("orga.example/gix")
        note = _checkpoint().note_text()
        signed = signer.sign_note(note)
        text, sig_lines = split_signed_note(signed)
        assert text == note
        assert len(sig_lines) == 1
        assert sig_lines[0].startswith("— orga.example/gix ")

    def test_tampered_text_fails(self):
        signer = Ed25519NoteSigner("orga.example/gix")
        signed = signer.sign_note(_checkpoint(n=5).note_text())
        tampered = signed.replace("\n5\n", "\n6\n")
        assert verify_note(tampered, [signer.verifier]) == ()

    def test_unknown_key_is_ignored_but_alone_rejects(self):
        signer = Ed25519NoteSigner("orga.example/gix")
        stranger = Ed25519NoteSigner("stranger.example/key")
        signed = signer.sign_note(_checkpoint().note_text())
        # Only a stranger's key: no known key verifies -> reject.
        assert verify_note(signed, [stranger.verifier]) == ()
        # Known + stranger: the known one verifies, stranger ignored.
        assert verify_note(signed, [stranger.verifier, signer.verifier]) == (
            "orga.example/gix",
        )

    def test_known_key_with_bad_signature_rejects_everything(self):
        """Fail-closed tightening documented in verify_note: a known key that
        signs garbage poisons the note even if another valid line exists."""
        signer = Ed25519NoteSigner("orga.example/gix")
        note = _checkpoint().note_text()
        signed = signer.sign_note(note)
        other_note = _checkpoint(n=9).note_text()
        wrong_sig_line = split_signed_note(signer.sign_note(other_note))[1][0]
        spliced = signed + wrong_sig_line + "\n"
        assert verify_note(spliced, [signer.verifier]) == ()

    def test_key_id_binds_name(self):
        """Same key bytes under a different name -> different key ID -> the
        signature is treated as unknown, not verified."""
        signer = Ed25519NoteSigner("orga.example/gix")
        renamed = Ed25519NoteVerifier(
            name="impostor.example/gix",
            public_key_raw=signer.verifier.public_key_raw,
        )
        signed = signer.sign_note(_checkpoint().note_text())
        assert verify_note(signed, [renamed]) == ()

    def test_signer_refuses_blank_lines_in_note(self):
        signer = Ed25519NoteSigner("orga.example/gix")
        with pytest.raises(ValueError):
            signer.sign_note("orga.example/gix\n\n5\n")

    def test_signed_note_key_id_matches_spec_construction(self):
        """Ed25519 signed-note key ID = SHA-256(name || 0x0A || 0x01 || pub)[:4]
        — recomputed by hand from the spec text."""
        signer = Ed25519NoteSigner("orga.example/gix")
        v = signer.verifier
        expected = hashlib.sha256(
            b"orga.example/gix\n\x01" + v.public_key_raw
        ).digest()[:4]
        assert v.key_id == expected
        _, (line,) = split_signed_note(signer.sign_note(_checkpoint().note_text()))
        blob = base64.b64decode(line.split(" ", 2)[2])
        assert blob[:4] == expected


class TestCosignatureV1:
    def _cosigned_line(self):
        signer = Ed25519NoteSigner("orga.example/gix")
        note = _checkpoint().note_text()
        signed = signer.sign_note(note)
        witness = Witness(
            "witness0.example/w",
            trusted_logs={"orga.example/gix": signer.verifier},
            clock=lambda: FIXED_CLOCK,
        )
        body = f"old 0\n\n{signed}"
        response = witness.add_checkpoint(body)
        assert response.cosigned, response.reason
        return witness, note, response.cosignature_line

    def test_blob_layout_4_8_64(self):
        witness, _, line = self._cosigned_line()
        blob = base64.b64decode(line.split(" ", 2)[2])
        assert len(blob) == 76  # 4 key ID + 8 timestamp + 64 Ed25519
        assert blob[:4] == witness.descriptor.key_id
        assert int.from_bytes(blob[4:12], "big") == FIXED_CLOCK

    def test_key_id_matches_spec_construction(self):
        """cosignature/v1 key ID = SHA-256(name || 0x0A || 0x04 || pub)[:4]."""
        witness, _, line = self._cosigned_line()
        expected = hashlib.sha256(
            b"witness0.example/w\n\x04" + witness.descriptor.public_key_raw
        ).digest()[:4]
        assert witness.descriptor.key_id == expected

    def test_signed_message_matches_spec_construction(self):
        """Re-derive the signed message by hand (header line + time line +
        note body) and verify the raw Ed25519 signature directly — independent
        of verify_cosignature_line."""
        witness, note, line = self._cosigned_line()
        blob = base64.b64decode(line.split(" ", 2)[2])
        timestamp = int.from_bytes(blob[4:12], "big")
        message = (
            f"cosignature/v1\ntime {timestamp}\n".encode() + note.encode()
        )
        public = ed25519.Ed25519PublicKey.from_public_bytes(
            witness.descriptor.public_key_raw
        )
        public.verify(blob[12:], message)  # raises if wrong

    def test_verify_cosignature_line(self):
        witness, note, line = self._cosigned_line()
        assert verify_cosignature_line(line, note, witness.descriptor)

    def test_verify_rejects_wrong_note(self):
        witness, _, line = self._cosigned_line()
        other_note = _checkpoint(n=9).note_text()
        assert not verify_cosignature_line(line, other_note, witness.descriptor)

    def test_verify_rejects_doctored_timestamp(self):
        witness, note, line = self._cosigned_line()
        prefix, b64 = line.rsplit(" ", 1)
        blob = bytearray(base64.b64decode(b64))
        blob[4:12] = (FIXED_CLOCK + 1).to_bytes(8, "big")
        doctored = f"{prefix} {base64.b64encode(bytes(blob)).decode()}"
        assert not verify_cosignature_line(doctored, note, witness.descriptor)

    def test_verify_rejects_zero_timestamp(self):
        witness, note, line = self._cosigned_line()
        prefix, b64 = line.rsplit(" ", 1)
        blob = bytearray(base64.b64decode(b64))
        blob[4:12] = (0).to_bytes(8, "big")
        doctored = f"{prefix} {base64.b64encode(bytes(blob)).decode()}"
        assert not verify_cosignature_line(doctored, note, witness.descriptor)

    def test_verify_rejects_wrong_witness(self):
        witness, note, line = self._cosigned_line()
        other = Witness(
            "witness1.example/w",
            trusted_logs={},
            clock=lambda: FIXED_CLOCK,
        )
        assert not verify_cosignature_line(line, note, other.descriptor)

    def test_zero_clock_is_floored_not_zero(self):
        """The spec MUST: a cosignature timestamp is never zero, even from a
        broken clock."""
        signer = Ed25519NoteSigner("orga.example/gix")
        witness = Witness(
            "witness0.example/w",
            trusted_logs={"orga.example/gix": signer.verifier},
            clock=lambda: 0,
        )
        signed = signer.sign_note(_checkpoint().note_text())
        response = witness.add_checkpoint(f"old 0\n\n{signed}")
        assert response.cosigned
        blob = base64.b64decode(response.cosignature_line.split(" ", 2)[2])
        assert int.from_bytes(blob[4:12], "big") == 1
