"""
gix_witness (Wave 2 / L6) — C2SP tlog-witness cosigning semantics, in-tree.

Claim ceiling (say exactly this, nothing more): in-tree implementation of C2SP
tlog-witness cosigning semantics, exercised against self-hosted witness
instances — protocol logic, NOT organizational independence.

What a witness is (c2sp.org/tlog-witness, re-fetched 2026-06-11): an entity
with its own key that tracks, per log origin, the latest checkpoint it
observed and verified, and that REFUSES to cosign any checkpoint it cannot
prove consistent with that record. Non-equivocation is exactly this refusal:
a log operator who forks or rewrites history cannot collect cosignatures on
the forked view from witnesses that saw the honest one.

The verification sequence implemented by :meth:`Witness.add_checkpoint`
mirrors the spec's, with outcomes named after the HTTP analogs:

1. parse the request body (``old <size>`` line, ≤63 base64 proof lines,
   empty line, signed checkpoint)        → ``MALFORMED`` (400) on violation;
2. unknown origin                        → ``UNKNOWN_LOG`` (404);
3. no trusted-key signature verifies     → ``LOG_UNAUTHENTICATED`` (403);
4. old size > checkpoint size            → ``MALFORMED`` (400);
5. old size ≠ witness's latest size      → ``CONFLICT`` (409, latest size
   returned so an honest client can retry from there);
6. equal sizes with different roots      → ``CONFLICT`` (409 — equivocation);
7. consistency proof fails               → ``BAD_CONSISTENCY_PROOF`` (422);
8. otherwise: persist + cosign           → ``COSIGNED`` (200).
Check-and-persist runs under one lock — the spec's atomicity MUST.

Cosignatures are cosignature/v1 (c2sp.org/tlog-cosignature, re-fetched
2026-06-11): signed message = ``cosignature/v1\\n`` + ``time <t>\\n`` + the
whole note body; signature blob = 4-byte key ID || big-endian u64 timestamp ||
Ed25519 signature; Ed25519 key ID = SHA-256(name || 0x0A || 0x04 || key)[:4].

``federated`` is structurally False this wave
---------------------------------------------
:func:`verify_cosigned_checkpoint` reports ``federated=False`` with reason
:data:`FEDERATED_FALSE_REASON` whenever any cosigner is not
``EXTERNAL_FEDERATED`` — and no in-tree constructor will produce an
``EXTERNAL_FEDERATED`` witness or descriptor (both raise). Organizational
independence is a fact about the world, not about this codebase; code cannot
self-assert it (the same structural-unconstructibility discipline as L12's
``qif_certified: Literal[False]``). The ``TEX_GIX_WITNESS`` env flag gates
wiring in ``main.py`` only; NO function in this module reads it — flipping it
can never promote in-process witnesses to "independent orgs".

Name disambiguation: ``evidence/chain.py``'s ``prior_link_witness`` is a
*predecessor record hash* used to verify a chain slice — it is NOT a cosigner
and carries no key. The "witness" here is the C2SP tlog-witness sense.

A process restart drops in-memory witness and ledger state: a restarted log
presents as a fork and is refused (tested). Checkpoint continuity across
restarts is NOT claimed.

Maturity: ``research-early``.
"""

from __future__ import annotations

import base64
import hashlib
import threading
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from tex.interchange.gix import (
    Checkpoint,
    Ed25519NoteVerifier,
    empty_root,
    split_signed_note,
    verify_consistency,
    verify_note,
)

__all__ = [
    "CheckpointVerification",
    "CosignedCheckpoint",
    "FEDERATED_FALSE_REASON",
    "Witness",
    "WitnessDescriptor",
    "WitnessOutcome",
    "WitnessProvenance",
    "WitnessResponse",
    "gather_cosignatures",
    "verify_cosignature_line",
    "verify_cosigned_checkpoint",
]

# cosignature/v1 algorithm byte for Ed25519 (c2sp.org/tlog-cosignature).
_COSIG_ALG_ED25519 = b"\x04"
_COSIG_HEADER = "cosignature/v1\n"
_SIG_LINE_PREFIX = "— "
# "zero to 63 consistency proof lines" — spec bound on the request body.
_MAX_PROOF_LINES = 63

FEDERATED_FALSE_REASON = (
    "gix_witnesses_self_hosted_not_independent_orgs: every cosigner is an "
    "in-process/self-hosted instance under one operator; the cosignatures "
    "prove non-equivocation protocol semantics only, never organizational "
    "independence (North-Star L6 is out of scope this wave)"
)


class WitnessProvenance(StrEnum):
    """Where a witness actually runs. Determines what its cosignature may
    honestly claim."""

    IN_PROCESS = "in_process"  # constructed inside this Python process
    SELF_HOSTED = "self_hosted"  # separate process, SAME operator
    # The North-Star seam: a real, independently-operated witness (live C2SP
    # OmniWitness federation). Deliberately unconstructible in-tree — both
    # Witness and WitnessDescriptor raise on it, so `federated=True` is
    # structurally unreachable this wave.
    EXTERNAL_FEDERATED = "external_federated"


_INDEPENDENCE_REFUSAL = (
    "organizational independence cannot be asserted by in-tree construction; "
    "EXTERNAL_FEDERATED is the North-Star (live OmniWitness federation) seam "
    "and has no in-tree constructor this wave"
)


class WitnessOutcome(StrEnum):
    """Typed outcome of add-checkpoint, named for the C2SP HTTP analogs."""

    COSIGNED = "cosigned"  # 200
    MALFORMED = "malformed"  # 400
    LOG_UNAUTHENTICATED = "log_unauthenticated"  # 403
    UNKNOWN_LOG = "unknown_log"  # 404
    CONFLICT = "conflict"  # 409
    BAD_CONSISTENCY_PROOF = "bad_consistency_proof"  # 422


_HTTP_ANALOG = {
    WitnessOutcome.COSIGNED: 200,
    WitnessOutcome.MALFORMED: 400,
    WitnessOutcome.LOG_UNAUTHENTICATED: 403,
    WitnessOutcome.UNKNOWN_LOG: 404,
    WitnessOutcome.CONFLICT: 409,
    WitnessOutcome.BAD_CONSISTENCY_PROOF: 422,
}


@dataclass(frozen=True)
class WitnessResponse:
    """One witness's answer to one add-checkpoint request."""

    outcome: WitnessOutcome
    reason: str
    cosignature_line: str | None = None
    # On CONFLICT, the spec returns the latest cosigned size so the client can
    # fetch the right consistency proof and retry.
    latest_size: int | None = None

    @property
    def http_analog(self) -> int:
        return _HTTP_ANALOG[self.outcome]

    @property
    def cosigned(self) -> bool:
        return self.outcome is WitnessOutcome.COSIGNED


@dataclass(frozen=True)
class WitnessDescriptor:
    """A relying party's pinned view of one witness: name, raw Ed25519 public
    key, and provenance. Raises on EXTERNAL_FEDERATED — see the module banner.
    """

    name: str
    public_key_raw: bytes
    provenance: WitnessProvenance

    def __post_init__(self) -> None:
        if self.provenance is WitnessProvenance.EXTERNAL_FEDERATED:
            raise ValueError(_INDEPENDENCE_REFUSAL)
        if len(self.public_key_raw) != 32:
            raise ValueError("Ed25519 public key must be 32 raw bytes")

    @property
    def key_id(self) -> bytes:
        return hashlib.sha256(
            self.name.encode("utf-8")
            + b"\n"
            + _COSIG_ALG_ED25519
            + self.public_key_raw
        ).digest()[:4]


def _parse_add_checkpoint_body(
    body: str,
) -> tuple[int, tuple[str, ...], str] | str:
    """Parse the wire body → (old_size, proof_hex, signed_note), or a reason
    string when malformed."""
    first_nl = body.find("\n")
    if first_nl < 0:
        return "body has no old-size line"
    old_line = body[:first_nl]
    if not old_line.startswith("old "):
        return "first line must be 'old <size>'"
    size_text = old_line[4:]
    if size_text != "0" and (
        not size_text.isdigit() or size_text.startswith("0")
    ):
        return "old size must be ASCII decimal with no leading zeroes"
    old_size = int(size_text)

    rest = body[first_nl + 1 :]
    proof: list[str] = []
    while True:
        nl = rest.find("\n")
        if nl < 0:
            return "body has no empty-line separator before the checkpoint"
        line = rest[:nl]
        rest = rest[nl + 1 :]
        if line == "":
            break
        if len(proof) >= _MAX_PROOF_LINES:
            return "more than 63 consistency proof lines"
        try:
            raw = base64.b64decode(line, validate=True)
        except Exception:  # noqa: BLE001 — any b64 failure is malformed
            return "consistency proof line is not valid base64"
        if len(raw) != 32:
            return "consistency proof hash must be 32 bytes"
        proof.append(raw.hex())
    if not rest:
        return "body has no checkpoint after the empty line"
    return old_size, tuple(proof), rest


class Witness:
    """One self-hosted C2SP-semantics witness instance.

    ``trusted_logs`` maps log origin → the log's pinned note-verification key.
    ``clock`` is injectable for deterministic tests; cosignature timestamps
    must never be zero (spec MUST), so a non-positive clock reading is floored
    to 1.
    """

    def __init__(
        self,
        name: str,
        *,
        trusted_logs: Mapping[str, Ed25519NoteVerifier],
        provenance: WitnessProvenance = WitnessProvenance.IN_PROCESS,
        clock: Callable[[], int] | None = None,
    ) -> None:
        if provenance is WitnessProvenance.EXTERNAL_FEDERATED:
            raise ValueError(_INDEPENDENCE_REFUSAL)
        if not name or "\n" in name:
            raise ValueError("witness name must be one non-empty line")
        self._name = name
        self._provenance = provenance
        self._trusted: dict[str, Ed25519NoteVerifier] = dict(trusted_logs)
        # origin -> (size, root) of the latest verified checkpoint. The spec
        # requires check-and-persist to be atomic; one lock serializes it.
        self._latest: dict[str, tuple[int, bytes]] = {}
        self._lock = threading.Lock()
        self._clock = clock or (lambda: int(time.time()))
        self._private = ed25519.Ed25519PrivateKey.generate()
        self._public_raw = self._private.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )

    @property
    def name(self) -> str:
        return self._name

    @property
    def descriptor(self) -> WitnessDescriptor:
        return WitnessDescriptor(
            name=self._name,
            public_key_raw=self._public_raw,
            provenance=self._provenance,
        )

    def latest_size(self, origin: str) -> int:
        with self._lock:
            entry = self._latest.get(origin)
            return entry[0] if entry else 0

    # ------------------------------------------------------------------ core
    def add_checkpoint(self, body: str) -> WitnessResponse:
        """The c2sp.org/tlog-witness add-checkpoint state machine. See the
        module banner for the numbered sequence and HTTP analogs."""
        parsed = _parse_add_checkpoint_body(body)
        if isinstance(parsed, str):
            return WitnessResponse(WitnessOutcome.MALFORMED, parsed)
        old_size, proof, signed_note = parsed

        try:
            note_text, _ = split_signed_note(signed_note)
            checkpoint = Checkpoint.parse(note_text)
        except ValueError as exc:
            return WitnessResponse(WitnessOutcome.MALFORMED, str(exc))

        log_verifier = self._trusted.get(checkpoint.origin)
        if log_verifier is None:
            return WitnessResponse(
                WitnessOutcome.UNKNOWN_LOG,
                f"origin {checkpoint.origin!r} is not a log this witness serves",
            )
        if not verify_note(signed_note, [log_verifier]):
            return WitnessResponse(
                WitnessOutcome.LOG_UNAUTHENTICATED,
                "no signature from a trusted key for the origin verifies",
            )
        if old_size > checkpoint.tree_size:
            return WitnessResponse(
                WitnessOutcome.MALFORMED,
                "the old size MUST be equal to or lower than the checkpoint size",
            )

        with self._lock:
            entry = self._latest.get(checkpoint.origin)
            latest_size = entry[0] if entry else 0
            latest_root = entry[1] if entry else None

            if old_size != latest_size:
                return WitnessResponse(
                    WitnessOutcome.CONFLICT,
                    "old size does not match this witness's latest checkpoint",
                    latest_size=latest_size,
                )

            if old_size == checkpoint.tree_size:
                # Same size: the roots must be identical; differing roots at
                # one size are two views of "the same" log — equivocation.
                if proof:
                    return WitnessResponse(
                        WitnessOutcome.BAD_CONSISTENCY_PROOF,
                        "a same-size submission admits no consistency proof",
                    )
                if latest_root is not None:
                    if latest_root != checkpoint.root_hash:
                        return WitnessResponse(
                            WitnessOutcome.CONFLICT,
                            "root hash differs at an equal tree size "
                            "(equivocation)",
                            latest_size=latest_size,
                        )
                elif checkpoint.root_hash.hex() != empty_root():
                    # size 0 == old size 0: the empty tree's root is pinned
                    # by RFC 9162; anything else is not a real empty tree.
                    return WitnessResponse(
                        WitnessOutcome.BAD_CONSISTENCY_PROOF,
                        "size-0 checkpoint root must be the RFC 9162 empty root",
                    )
            elif old_size == 0:
                # First observation of this log: nothing to be consistent
                # WITH. Fail-closed corner (exact spec status not re-quoted):
                # a proof offered from size 0 is refused rather than ignored.
                if proof:
                    return WitnessResponse(
                        WitnessOutcome.BAD_CONSISTENCY_PROOF,
                        "no consistency proof is admissible from size 0",
                    )
            else:
                assert latest_root is not None  # old_size == latest_size > 0
                if not verify_consistency(
                    old_size,
                    latest_root.hex(),
                    checkpoint.tree_size,
                    checkpoint.root_hash.hex(),
                    proof,
                ):
                    return WitnessResponse(
                        WitnessOutcome.BAD_CONSISTENCY_PROOF,
                        "consistency proof does not verify against the "
                        "latest observed checkpoint",
                    )

            # Atomic with the checks above (same lock): persist, then cosign.
            self._latest[checkpoint.origin] = (
                checkpoint.tree_size,
                checkpoint.root_hash,
            )
            line = self._cosign(note_text)
            return WitnessResponse(
                WitnessOutcome.COSIGNED, "cosigned", cosignature_line=line
            )

    def _cosign(self, note_text: str) -> str:
        """Produce one cosignature/v1 note-signature line over ``note_text``."""
        timestamp = max(1, int(self._clock()))  # MUST NOT be zero
        message = (
            _COSIG_HEADER.encode("ascii")
            + f"time {timestamp}\n".encode("ascii")
            + note_text.encode("utf-8")
        )
        signature = self._private.sign(message)
        blob = (
            self.descriptor.key_id + timestamp.to_bytes(8, "big") + signature
        )
        b64 = base64.b64encode(blob).decode("ascii")
        return f"{_SIG_LINE_PREFIX}{self._name} {b64}"


def verify_cosignature_line(
    line: str, note_text: str, descriptor: WitnessDescriptor
) -> bool:
    """Verify one cosignature/v1 line against a pinned witness descriptor.

    Recomputes the signed message (header + ``time <t>`` from the embedded
    big-endian u64 timestamp + note body) and the 4-byte key ID. Fail-closed:
    any malformation returns False.
    """
    if not line.startswith(_SIG_LINE_PREFIX):
        return False
    rest = line[len(_SIG_LINE_PREFIX) :].rstrip("\n")
    sep = rest.rfind(" ")
    if sep <= 0:
        return False
    name, b64 = rest[:sep], rest[sep + 1 :]
    if name != descriptor.name:
        return False
    try:
        blob = base64.b64decode(b64, validate=True)
    except Exception:  # noqa: BLE001
        return False
    # 4 (key ID) + 8 (timestamp) + 64 (Ed25519 signature)
    if len(blob) != 76:
        return False
    key_id, ts_bytes, signature = blob[:4], blob[4:12], blob[12:]
    if key_id != descriptor.key_id:
        return False
    timestamp = int.from_bytes(ts_bytes, "big")
    if timestamp == 0:
        return False  # the timestamp MUST NOT be zero
    message = (
        _COSIG_HEADER.encode("ascii")
        + f"time {timestamp}\n".encode("ascii")
        + note_text.encode("utf-8")
    )
    try:
        ed25519.Ed25519PublicKey.from_public_bytes(
            descriptor.public_key_raw
        ).verify(signature, message)
        return True
    except (InvalidSignature, ValueError):
        return False


@dataclass(frozen=True)
class CosignedCheckpoint:
    """A log-signed checkpoint note plus the cosignatures it gathered and the
    refusals it provoked (witness name → response)."""

    signed_note: str
    cosignature_lines: tuple[str, ...]
    refusals: tuple[tuple[str, WitnessResponse], ...] = ()

    @property
    def refusal_count(self) -> int:
        return len(self.refusals)


def gather_cosignatures(
    add_checkpoint_body: str, witnesses: Sequence[Witness]
) -> CosignedCheckpoint:
    """Submit one add-checkpoint body to each witness; collect cosignatures
    and refusals. Refusals are first-class — "≥3 witnesses refuse" is the
    non-equivocation headline, not an error path."""
    parsed = _parse_add_checkpoint_body(add_checkpoint_body)
    if isinstance(parsed, str):
        raise ValueError(f"malformed add-checkpoint body: {parsed}")
    _, _, signed_note = parsed
    lines: list[str] = []
    refusals: list[tuple[str, WitnessResponse]] = []
    for witness in witnesses:
        response = witness.add_checkpoint(add_checkpoint_body)
        if response.cosigned and response.cosignature_line:
            lines.append(response.cosignature_line)
        else:
            refusals.append((witness.name, response))
    return CosignedCheckpoint(
        signed_note=signed_note,
        cosignature_lines=tuple(lines),
        refusals=tuple(refusals),
    )


@dataclass(frozen=True)
class CheckpointVerification:
    """What org B may conclude from a cosigned checkpoint — no more.

    ``federated`` is False whenever any counted cosigner is not
    EXTERNAL_FEDERATED; since no in-tree constructor produces an
    EXTERNAL_FEDERATED descriptor, it is structurally False this wave.
    """

    checkpoint: Checkpoint | None
    log_signature_valid: bool
    valid_cosigners: tuple[str, ...]
    quorum: int
    quorum_met: bool
    federated: bool
    federated_reason: str
    reason: str


def verify_cosigned_checkpoint(
    cosigned: CosignedCheckpoint,
    *,
    log_verifier: Ed25519NoteVerifier,
    roster: Sequence[WitnessDescriptor],
    quorum: int = 3,
) -> CheckpointVerification:
    """Org B's verification of org A's witnessed checkpoint.

    Checks (1) the log's own note signature against the pinned log key and
    (2) each cosignature line against the pinned witness roster, deduplicated
    by witness name. ``quorum_met`` requires both (1) and ≥``quorum`` distinct
    valid cosigners.

    Deliberately reads NO environment flag: ``TEX_GIX_WITNESS`` gates wiring
    in main.py, never trust here.
    """
    if quorum < 1:
        raise ValueError("quorum must be >= 1")
    failed = CheckpointVerification(
        checkpoint=None,
        log_signature_valid=False,
        valid_cosigners=(),
        quorum=quorum,
        quorum_met=False,
        federated=False,
        federated_reason=FEDERATED_FALSE_REASON,
        reason="",
    )
    try:
        note_text, _ = split_signed_note(cosigned.signed_note)
        checkpoint = Checkpoint.parse(note_text)
    except ValueError as exc:
        return _replace(failed, reason=f"malformed signed checkpoint: {exc}")

    if not verify_note(cosigned.signed_note, [log_verifier]):
        return _replace(
            failed,
            checkpoint=checkpoint,
            reason="log note signature does not verify against the pinned key",
        )

    by_name = {d.name: d for d in roster}
    valid: list[str] = []
    for line in cosigned.cosignature_lines:
        for name, descriptor in by_name.items():
            if name in valid:
                continue
            if verify_cosignature_line(line, note_text, descriptor):
                valid.append(name)
                break
    quorum_met = len(valid) >= quorum

    # Principled federation computation; True is structurally unreachable
    # in-tree because WitnessDescriptor refuses EXTERNAL_FEDERATED.
    non_external = [
        by_name[name]
        for name in valid
        if by_name[name].provenance is not WitnessProvenance.EXTERNAL_FEDERATED
    ]
    federated = quorum_met and not non_external and len(valid) > 0

    return CheckpointVerification(
        checkpoint=checkpoint,
        log_signature_valid=True,
        valid_cosigners=tuple(valid),
        quorum=quorum,
        quorum_met=quorum_met,
        federated=federated,
        federated_reason="" if federated else FEDERATED_FALSE_REASON,
        reason="ok" if quorum_met else (
            f"only {len(valid)} of the required {quorum} cosignatures verify"
        ),
    )


def _replace(base: CheckpointVerification, **kwargs: object) -> CheckpointVerification:
    from dataclasses import replace

    return replace(base, **kwargs)  # type: ignore[arg-type]
