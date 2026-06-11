"""
GIX (Wave 2 / L6) — a transparency-log view over sealed governance verdicts.

What this module is
-------------------
An RFC 9162 Merkle transparency log whose *leaves are governance verdicts*
(the ``record_hash`` of each :class:`~tex.provenance.ledger.SealedFactRecord`),
plus the two proof primitives ``ecosystem/_window.py`` declared TODO:

* **Inclusion proofs** (RFC 9162 §2.1.3) — "this verdict record is in the
  checkpointed log".
* **Consistency proofs** (RFC 9162 §2.1.4) — "this checkpoint extends that
  earlier checkpoint without rewriting history". Consistency proofs are the
  mechanism behind non-equivocation: a witness refuses to cosign a checkpoint
  it cannot prove consistent with what it already observed (``gix_witness``).

Checkpoints are serialized and signed in the C2SP wire formats, transcribed
from the specs re-fetched 2026-06-11 and unit-tested against hand-derived
constructions. (Cross-implementation interop — e.g. against Go's
golang.org/x/mod/sumdb/note — has NOT been exercised; that claim is
UNVERIFIED until a second implementation consumes these bytes.)

* checkpoint note body — https://c2sp.org/tlog-checkpoint
  (origin line, ASCII-decimal tree size, base64 root hash, optional
  extension lines).
* signed note — https://c2sp.org/signed-note (text, blank line, then
  "— <name> base64(4-byte key ID || Ed25519 signature)" lines; Ed25519
  key ID = SHA-256(name || 0x0A || 0x01 || public key)[:4]).

Claim ceiling (say exactly this, nothing more)
----------------------------------------------
In-tree implementation of C2SP tlog-witness cosigning semantics, exercised
against self-hosted witness instances — protocol logic, NOT organizational
independence. The North-Star (live external C2SP OmniWitness federation
across real independent orgs, ROADMAP.md "L6 →") is OUT of scope; see
``gix_witness.py`` for the structural ``federated=False`` gate.

Three different proofs — never conflate them
--------------------------------------------
* the ledger hash **chain** proves *integrity* (``SealedFactLedger.verify_chain``);
* a ledger ECDSA-P256 **signature** proves *authorship* of one record
  (``SealedFactLedger.verify_signatures``);
* a witness-cosigned **checkpoint** proves *non-equivocation* — the log
  operator showed everyone the same log (this package's new property).

Tree-math provenance
--------------------
The ONLY in-tree Merkle tree this module trusts is the RFC 9162 MTH in
``tex/ecosystem/_window.py`` (correct 0x00/0x01 domain separation and k-split).
``vet/scitt.py``'s tree is deliberately NOT reused: it duplicates odd leaves,
has no domain separation, and uses a zero-bytes empty root — citing it would
falsify the RFC 9162 claim.

Operational honesty
-------------------
* The publisher is **pull-based**: transparency logs publish signed tree heads
  on demand or on a cadence; they do not push per-leaf. ``None`` ledger or an
  unset ``TEX_GIX_WITNESS`` flag ⇒ ``build_checkpoint_publisher`` returns
  ``None`` and nothing runs (inert, fail-closed to today's behaviour).
* The decision ledger is in-memory (``TEX_SEAL_DECISIONS`` opt-in): a process
  restart starts a fresh chain, which witnesses correctly treat as a fork and
  refuse. **Checkpoint continuity across restarts is NOT claimed.**

Maturity: ``research-early``.
"""

from __future__ import annotations

import base64
import hashlib
import os
import threading
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from typing import Any, Protocol

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

# The one real RFC 9162 MTH (leaf/inner domain separation + k-split). The
# _INNER_PREFIX constant is normative in _window.py ("do not rename"); the
# proof verifiers below must combine nodes with exactly that prefix, so it is
# imported rather than re-declared — one source of hash truth.
from tex.ecosystem._window import (  # noqa: F401  (empty_root re-exported for callers)
    _INNER_PREFIX,
    empty_root,
    leaf_hash,
    merkle_root,
)

__all__ = [
    "Checkpoint",
    "CheckpointPublisher",
    "Ed25519NoteSigner",
    "Ed25519NoteVerifier",
    "SignedCheckpoint",
    "build_add_checkpoint_body",
    "build_checkpoint_publisher",
    "consistency_path",
    "empty_root",
    "get_active_checkpoint_publisher",
    "inclusion_path",
    "merkle_root",
    "split_signed_note",
    "verify_consistency",
    "verify_inclusion",
    "verify_note",
]

# Signed-note algorithm byte for Ed25519 (c2sp.org/signed-note, re-fetched
# 2026-06-11): key ID = SHA-256(name || 0x0A || 0x01 || 32-byte public key)[:4].
_NOTE_ALG_ED25519 = b"\x01"
# Em dash (U+2014) + space — the normative signature-line prefix.
_SIG_LINE_PREFIX = "— "

GIX_ENV_FLAG = "TEX_GIX_WITNESS"
DEFAULT_GIX_ORIGIN = "tex.local/gix-decision-log"


# --------------------------------------------------------------------------
# RFC 9162 §2.1.3 / §2.1.4 — proof generation
#
# Generation recurses exactly like the RFC text and computes every subtree
# hash via ``_window.merkle_root`` over the corresponding slice (MTH of a
# sub-list IS the MTH of that slice). O(n log n) hashing per proof — fine at
# governance-log sizes, and it keeps all tree hashing in _window.py.
# --------------------------------------------------------------------------


def _largest_power_of_two_below(n: int) -> int:
    """k = largest power of two with k < n, for n >= 2 (RFC 9162 §2.1)."""
    k = 1
    while (k << 1) < n:
        k <<= 1
    return k


def inclusion_path(
    leaf_index: int, record_hashes_hex: Sequence[str]
) -> tuple[str, ...]:
    """RFC 9162 §2.1.3.1 ``PATH(m, D[n])`` — the audit path for one leaf.

    Returns hex-encoded node hashes, leaf-to-root order. Raises ``ValueError``
    on an out-of-range index or an empty tree.
    """
    n = len(record_hashes_hex)
    if n == 0:
        raise ValueError("inclusion_path: empty tree has no inclusion proofs")
    if not (0 <= leaf_index < n):
        raise ValueError(
            f"inclusion_path: leaf_index {leaf_index} out of range for n={n}"
        )
    if n == 1:
        return ()
    k = _largest_power_of_two_below(n)
    if leaf_index < k:
        return inclusion_path(leaf_index, record_hashes_hex[:k]) + (
            merkle_root(record_hashes_hex[k:]),
        )
    return inclusion_path(leaf_index - k, record_hashes_hex[k:]) + (
        merkle_root(record_hashes_hex[:k]),
    )


def consistency_path(
    first_size: int, record_hashes_hex: Sequence[str]
) -> tuple[str, ...]:
    """RFC 9162 §2.1.4.1 ``PROOF(m, D[n])`` — proof that the size-``m`` prefix
    tree is a prefix of this tree.

    Defined for ``0 < first_size <= n``; ``first_size == n`` returns the empty
    proof (same tree). ``first_size == 0`` raises — consistency with the empty
    tree is vacuous and handled by the caller (a witness bootstrapping from
    size 0 needs no proof).
    """
    n = len(record_hashes_hex)
    if not (0 < first_size <= n):
        raise ValueError(
            f"consistency_path: first_size {first_size} out of range (0, {n}]"
        )
    if first_size == n:
        return ()
    return _subproof(first_size, tuple(record_hashes_hex), True)


def _subproof(m: int, d: tuple[str, ...], b: bool) -> tuple[str, ...]:
    """RFC 9162 §2.1.4.1 ``SUBPROOF(m, D[n], b)``, verbatim recursion."""
    n = len(d)
    if m == n:
        return () if b else (merkle_root(d),)
    k = _largest_power_of_two_below(n)
    if m <= k:
        return _subproof(m, d[:k], b) + (merkle_root(d[k:]),)
    return _subproof(m - k, d[k:], False) + (merkle_root(d[:k]),)


# --------------------------------------------------------------------------
# RFC 9162 §2.1.3.2 / §2.1.4.2 — proof verification (succinct: no leaves)
# --------------------------------------------------------------------------


def _node(left: bytes, right: bytes) -> bytes:
    """RFC 9162 inner node: ``H(0x01 || left || right)``."""
    return hashlib.sha256(_INNER_PREFIX + left + right).digest()


def _decode_hash_list(items: Sequence[str]) -> list[bytes] | None:
    """Hex-decode a proof path; None on any malformed/non-32-byte node."""
    out: list[bytes] = []
    for item in items:
        try:
            raw = bytes.fromhex(item)
        except (TypeError, ValueError):
            return None
        if len(raw) != 32:
            return None
        out.append(raw)
    return out


def verify_inclusion(
    record_hash_hex: str,
    leaf_index: int,
    tree_size: int,
    proof_hex: Sequence[str],
    root_hex: str,
) -> bool:
    """RFC 9162 §2.1.3.2 inclusion verification — returns ``True`` iff
    ``record_hash_hex`` is the leaf at ``leaf_index`` of the size-``tree_size``
    tree with root ``root_hex``.

    Succinct on purpose: the verifier holds only the checkpoint root and the
    proof, never the log. Fail-closed: any malformed input returns ``False``.
    """
    if leaf_index < 0 or tree_size < 1 or leaf_index >= tree_size:
        return False
    try:
        r = bytes.fromhex(leaf_hash(record_hash_hex))
    except (TypeError, ValueError):
        return False
    expected_root = _decode_hash_list([root_hex])
    path = _decode_hash_list(proof_hex)
    if expected_root is None or path is None:
        return False

    fn, sn = leaf_index, tree_size - 1
    for p in path:
        if sn == 0:
            return False
        if (fn & 1) or fn == sn:
            r = _node(p, r)
            if not (fn & 1):
                while fn != 0 and not (fn & 1):
                    fn >>= 1
                    sn >>= 1
        else:
            r = _node(r, p)
        fn >>= 1
        sn >>= 1
    return sn == 0 and r == expected_root[0]


def verify_consistency(
    first_size: int,
    first_root_hex: str,
    second_size: int,
    second_root_hex: str,
    proof_hex: Sequence[str],
) -> bool:
    """RFC 9162 §2.1.4.2 consistency verification — ``True`` iff the
    size-``first_size`` tree with root ``first_root_hex`` is a prefix of the
    size-``second_size`` tree with root ``second_root_hex``.

    Edge semantics (fail-closed):
    * ``first_size == 0``: consistent with anything, but only with an EMPTY
      proof and the canonical empty root (``SHA-256("")``) as ``first_root``.
    * ``first_size == second_size``: empty proof and identical roots required.
    * otherwise: the RFC algorithm verbatim (including the power-of-two
      prepend in step 2).
    """
    if first_size < 0 or second_size < first_size:
        return False
    roots = _decode_hash_list([first_root_hex, second_root_hex])
    if roots is None:
        return False
    first_root, second_root = roots
    if first_size == 0:
        return len(proof_hex) == 0 and first_root.hex() == empty_root()
    if first_size == second_size:
        return len(proof_hex) == 0 and first_root == second_root

    path = _decode_hash_list(proof_hex)
    if path is None or not path:
        # Step 1: "If consistency_path is an empty array, stop and fail."
        return False
    if first_size & (first_size - 1) == 0:
        # Step 2: "If first is an exact power of 2, prepend first_hash."
        path = [first_root, *path]

    fn, sn = first_size - 1, second_size - 1
    # Step 4: right-shift while LSB(fn) is set.
    while fn & 1:
        fn >>= 1
        sn >>= 1
    fr = sr = path[0]
    for c in path[1:]:
        if sn == 0:
            return False
        if (fn & 1) or fn == sn:
            fr = _node(c, fr)
            sr = _node(c, sr)
            if not (fn & 1):
                while fn != 0 and not (fn & 1):
                    fn >>= 1
                    sn >>= 1
        else:
            sr = _node(sr, c)
        fn >>= 1
        sn >>= 1
    return fr == first_root and sr == second_root and sn == 0


# --------------------------------------------------------------------------
# C2SP tlog-checkpoint note body (c2sp.org/tlog-checkpoint)
# --------------------------------------------------------------------------


def _has_control_chars(line: str) -> bool:
    return any(ord(ch) < 0x20 for ch in line)


@dataclass(frozen=True)
class Checkpoint:
    """One parsed checkpoint note body: origin / tree size / root hash
    (+ opaque extension lines). ``root_hash`` is the raw 32-byte RFC 9162 root.
    """

    origin: str
    tree_size: int
    root_hash: bytes
    extension_lines: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.origin or "\n" in self.origin or _has_control_chars(self.origin):
            raise ValueError("checkpoint origin must be one non-empty clean line")
        if self.tree_size < 0:
            raise ValueError("checkpoint tree_size must be >= 0")
        if len(self.root_hash) != 32:
            raise ValueError("checkpoint root_hash must be 32 bytes (SHA-256)")
        for line in self.extension_lines:
            if not line or _has_control_chars(line):
                raise ValueError(
                    "extension lines must be non-empty and contain no control chars"
                )

    @property
    def root_hash_hex(self) -> str:
        return self.root_hash.hex()

    def note_text(self) -> str:
        """Serialize per c2sp.org/tlog-checkpoint: origin line, ASCII-decimal
        tree size (no leading zeroes), base64 root, extension lines — each
        newline-terminated."""
        lines = [
            self.origin,
            str(self.tree_size),
            base64.b64encode(self.root_hash).decode("ascii"),
            *self.extension_lines,
        ]
        return "\n".join(lines) + "\n"

    @staticmethod
    def parse(note_text: str) -> "Checkpoint":
        """Parse a note body. Raises ``ValueError`` on any format violation
        (missing lines, leading-zero size, non-32-byte root, control chars)."""
        if not note_text.endswith("\n"):
            raise ValueError("checkpoint note must end in a newline")
        lines = note_text[:-1].split("\n")
        if len(lines) < 3:
            raise ValueError("checkpoint note needs origin, size and root lines")
        origin, size_line, root_line, *extensions = lines
        if size_line != "0" and (
            not size_line.isdigit() or size_line.startswith("0")
        ):
            raise ValueError(
                "tree size must be ASCII decimal with no leading zeroes"
            )
        try:
            root = base64.b64decode(root_line, validate=True)
        except Exception as exc:  # noqa: BLE001 — any b64 failure is malformed
            raise ValueError(f"root hash is not valid base64: {exc}") from exc
        return Checkpoint(
            origin=origin,
            tree_size=int(size_line),
            root_hash=root,
            extension_lines=tuple(extensions),
        )


# --------------------------------------------------------------------------
# C2SP signed note (c2sp.org/signed-note) — Ed25519
# --------------------------------------------------------------------------


def _ed25519_key_id(name: str, alg_byte: bytes, public_key_raw: bytes) -> bytes:
    """4-byte key ID: ``SHA-256(name || 0x0A || alg || public key)[:4]``."""
    return hashlib.sha256(
        name.encode("utf-8") + b"\n" + alg_byte + public_key_raw
    ).digest()[:4]


@dataclass(frozen=True)
class Ed25519NoteVerifier:
    """A known signed-note key: name + raw Ed25519 public key (32 bytes)."""

    name: str
    public_key_raw: bytes

    def __post_init__(self) -> None:
        if len(self.public_key_raw) != 32:
            raise ValueError("Ed25519 public key must be 32 raw bytes")

    @property
    def key_id(self) -> bytes:
        return _ed25519_key_id(self.name, _NOTE_ALG_ED25519, self.public_key_raw)

    def verify(self, message: bytes, signature: bytes) -> bool:
        try:
            ed25519.Ed25519PublicKey.from_public_bytes(
                self.public_key_raw
            ).verify(signature, message)
            return True
        except (InvalidSignature, ValueError):
            return False


class Ed25519NoteSigner:
    """A signed-note signer (log identity). Keys are generated in-process —
    this is a *self-hosted* identity; nothing here asserts org independence."""

    def __init__(self, name: str) -> None:
        if not name or "\n" in name:
            raise ValueError("signer name must be one non-empty line")
        self._name = name
        self._private = ed25519.Ed25519PrivateKey.generate()
        self._public_raw = self._private.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )

    @property
    def name(self) -> str:
        return self._name

    @property
    def verifier(self) -> Ed25519NoteVerifier:
        return Ed25519NoteVerifier(name=self._name, public_key_raw=self._public_raw)

    def sign_note(self, note_text: str) -> str:
        """Return the full signed note: text, blank line, one signature line
        ``— <name> base64(key ID || signature)``."""
        if not note_text.endswith("\n") or "\n\n" in note_text:
            raise ValueError(
                "note text must end in a newline and contain no blank lines"
            )
        signature = self._private.sign(note_text.encode("utf-8"))
        blob = (
            _ed25519_key_id(self._name, _NOTE_ALG_ED25519, self._public_raw)
            + signature
        )
        b64 = base64.b64encode(blob).decode("ascii")
        return f"{note_text}\n{_SIG_LINE_PREFIX}{self._name} {b64}\n"


def split_signed_note(signed: str) -> tuple[str, tuple[str, ...]]:
    """Split a signed note into (text, signature lines). Raises ``ValueError``
    if the blank-line separator or any signature-line prefix is missing."""
    idx = signed.find("\n\n")
    if idx < 0:
        raise ValueError("signed note has no blank-line separator")
    text = signed[: idx + 1]
    sig_block = signed[idx + 2 :]
    lines = tuple(line for line in sig_block.split("\n") if line)
    if not lines:
        raise ValueError("signed note has no signature lines")
    for line in lines:
        if not line.startswith(_SIG_LINE_PREFIX):
            raise ValueError("signature line must start with em dash + space")
    return text, lines


def _parse_signature_line(line: str) -> tuple[str, bytes] | None:
    """Parse ``— <name> <base64 blob>`` → (name, blob); None if malformed."""
    if not line.startswith(_SIG_LINE_PREFIX):
        return None
    rest = line[len(_SIG_LINE_PREFIX) :]
    sep = rest.rfind(" ")
    if sep <= 0:
        return None
    name, b64 = rest[:sep], rest[sep + 1 :]
    try:
        blob = base64.b64decode(b64, validate=True)
    except Exception:  # noqa: BLE001
        return None
    return name, blob


def verify_note(
    signed: str, verifiers: Sequence[Ed25519NoteVerifier]
) -> tuple[str, ...]:
    """Verify a signed note against known keys; return the names that verified.

    Per c2sp.org/signed-note: signatures from unknown keys are ignored; with no
    verifying known key the note is rejected (empty tuple). One deliberate
    fail-closed tightening over the spec floor: a signature that *names a known
    key but fails to verify* rejects the whole note — a key holder signing
    garbage is worse evidence than an unknown key.
    """
    try:
        text, sig_lines = split_signed_note(signed)
    except ValueError:
        return ()
    by_name: dict[str, list[Ed25519NoteVerifier]] = {}
    for v in verifiers:
        by_name.setdefault(v.name, []).append(v)
    message = text.encode("utf-8")
    verified: list[str] = []
    for line in sig_lines:
        parsed = _parse_signature_line(line)
        if parsed is None:
            return ()  # malformed line: fail-closed
        name, blob = parsed
        if len(blob) < 4:
            return ()
        key_id, signature = blob[:4], blob[4:]
        for v in by_name.get(name, []):
            if v.key_id != key_id:
                continue  # known name, different key generation: ignore
            if v.verify(message, signature):
                verified.append(v.name)
            else:
                return ()  # known key, bad signature: reject everything
    return tuple(dict.fromkeys(verified))


# --------------------------------------------------------------------------
# Pull-based checkpoint publisher (the org-A side)
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class SignedCheckpoint:
    """A checkpoint plus its log-signed note (one consistent snapshot)."""

    checkpoint: Checkpoint
    signed_note: str
    # The record hashes at snapshot time — kept so proofs for THIS checkpoint
    # are generated from the same snapshot (no torn reads).
    record_hashes: tuple[str, ...] = field(repr=False, default=())


def build_add_checkpoint_body(
    old_size: int, proof_hex: Sequence[str], signed_note: str
) -> str:
    """Serialize a c2sp.org/tlog-witness add-checkpoint request body:
    ``old <size>`` line, base64 proof lines, empty line, signed checkpoint."""
    if old_size < 0:
        raise ValueError("old_size must be >= 0")
    nodes = _decode_hash_list(proof_hex)
    if nodes is None:
        raise ValueError("proof_hex contains a malformed hash")
    lines = [f"old {old_size}"]
    lines.extend(base64.b64encode(n).decode("ascii") for n in nodes)
    return "\n".join(lines) + "\n\n" + signed_note


class _RecordHashSource(Protocol):
    """Anything exposing ordered sealed records with a ``record_hash``.

    Satisfied by ``SealedFactLedger`` (provenance/ledger.py) and — because the
    record-hash math is byte-identical — by the EvidenceRecorder chain. The
    publisher stays chain-agnostic by consuming only 64-hex record_hash
    strings, exactly ``_window.leaf_hash``'s contract.
    """

    def list_all(self) -> Sequence[Any]: ...


class CheckpointPublisher:
    """Pull-based signed-tree-head publisher over an ordered record-hash
    sequence.

    Each ``current_signed_checkpoint()`` call reads ONE snapshot of the hashes
    and binds checkpoint + proof material to it. Calls at different times see
    different (append-only) snapshots — that is normal transparency-log
    operation, not a race.
    """

    def __init__(
        self,
        *,
        origin: str,
        read_record_hashes: Callable[[], Sequence[str]],
        signer: Ed25519NoteSigner | None = None,
    ) -> None:
        self._origin = origin
        self._read = read_record_hashes
        self._signer = signer or Ed25519NoteSigner(origin)

    @property
    def origin(self) -> str:
        return self._origin

    @property
    def log_verifier(self) -> Ed25519NoteVerifier:
        """The public key a relying party pins to verify this log's notes."""
        return self._signer.verifier

    def current_signed_checkpoint(self) -> SignedCheckpoint:
        hashes = tuple(self._read())
        root = bytes.fromhex(merkle_root(hashes))
        checkpoint = Checkpoint(
            origin=self._origin, tree_size=len(hashes), root_hash=root
        )
        return SignedCheckpoint(
            checkpoint=checkpoint,
            signed_note=self._signer.sign_note(checkpoint.note_text()),
            record_hashes=hashes,
        )

    def build_add_checkpoint_request(self, old_size: int) -> str:
        """One snapshot → one wire body: current signed checkpoint plus the
        consistency proof from ``old_size`` (empty for 0 / same-size)."""
        snapshot = self.current_signed_checkpoint()
        size = snapshot.checkpoint.tree_size
        if old_size in (0, size):
            proof: tuple[str, ...] = ()
        else:
            proof = consistency_path(old_size, snapshot.record_hashes)
        return build_add_checkpoint_body(old_size, proof, snapshot.signed_note)

    def inclusion_proof(
        self, leaf_index: int, snapshot: SignedCheckpoint
    ) -> tuple[str, ...]:
        """Inclusion proof for a leaf against a previously-taken snapshot, so
        proof and checkpoint can never be torn across appends."""
        return inclusion_path(leaf_index, snapshot.record_hashes)


# --------------------------------------------------------------------------
# THE main.py seam — one additive call at the composition root
# --------------------------------------------------------------------------

_active_publisher: CheckpointPublisher | None = None
_active_lock = threading.Lock()


def _flag_enabled() -> bool:
    # Mirrors the TEX_SEAL_DECISIONS parse shape (main.py M0 seam).
    return os.environ.get(GIX_ENV_FLAG, "").strip().lower() in {"1", "true", "yes"}


def build_checkpoint_publisher(
    decision_ledger: _RecordHashSource | None,
) -> CheckpointPublisher | None:
    """The 1-line ``main.py`` seam (Wave 2 / L6).

    Inert by default and fail-closed to today's behaviour: returns ``None``
    (and registers nothing) unless BOTH a decision ledger is wired (M0,
    ``TEX_SEAL_DECISIONS=1``) and ``TEX_GIX_WITNESS`` is set. The flag gates
    *wiring only* — it is never read by any verifier, and flipping it cannot
    promote in-process witnesses to independent orgs (see ``gix_witness``).
    """
    global _active_publisher
    with _active_lock:
        if decision_ledger is None or not _flag_enabled():
            _active_publisher = None
            return None
        origin = os.environ.get("TEX_GIX_ORIGIN", "").strip() or DEFAULT_GIX_ORIGIN
        publisher = CheckpointPublisher(
            origin=origin,
            read_record_hashes=lambda: tuple(
                record.record_hash for record in decision_ledger.list_all()
            ),
        )
        _active_publisher = publisher
        return publisher


def get_active_checkpoint_publisher() -> CheckpointPublisher | None:
    """The publisher registered by ``build_checkpoint_publisher``, if any."""
    with _active_lock:
        return _active_publisher
