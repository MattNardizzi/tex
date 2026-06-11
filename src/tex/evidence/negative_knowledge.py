"""
Negative-knowledge certificate (Wave 2 / L3) — verifiable non-membership over a
sealed ledger epoch, plus the count-conservation predicate.

What this certifies — and the exact honesty boundary
----------------------------------------------------
A :class:`NegativeKnowledgeCertificate` claims precisely this and nothing more:

    "No sealed fact with key K exists in THIS ledger epoch."

It must never be read as "Tex never saw X". The ROADMAP nickname for L3 is
"provable ignorance" — that phrase is NOT what this module delivers, and the
certificate vocabulary never uses it. Three structural facts bound the claim:

1. **The ledger is opt-in and empty by default.** DECISION sealing happens only
   when ``TEX_SEAL_DECISIONS=1`` (src/tex/main.py, the seal_decisions block);
   with no ledger wired, ``seal_decision`` is a no-op returning ``None``
   (decision_seal.py:94-95). Non-membership over an unsealed deployment is
   *vacuous* — the certificate says so in its own fields (``vacuous=True``).
2. **The ledger is purely in-memory** (``self._entries: list``, ledger.py:256;
   no durable write-through exists). A process restart erases the epoch. Every
   claim here is therefore scoped to one process-lifetime epoch, identified by
   its chain-head hash — never to "Tex's history".
3. **Sealing is lossy by design**: an append failure is logged and swallowed
   (decision_seal.py:98-104). Conservation and non-membership hold only over
   records actually in the chain.

The certificate carries ``complete=False`` and ``attempt_hook_present=False``
until the upstream attempt-sealing hook lands (see the scoping proposal below).
Until then ``n_attempts`` has no sealed source — it is trust-me — so the
count-conservation predicate reports ``UNGATED`` rather than pretending to hold.

Construction (research-early; not ZK, not lattice-based)
--------------------------------------------------------
* **Canonical key** = ``SealedFactRecord.payload_sha256``: deterministic,
  independently recomputable from ``fact.canonical_payload()`` (the ledger's own
  ``verify_chain`` recomputes it the same way, ledger.py:341).
  :func:`recompute_key` mirrors that computation so an auditor never has to
  trust the stored field.
* **Sorted-key accumulator**: the ledger does NOT maintain sorted order — we
  construct a sorted-unique key list and Merkle-commit it via the existing
  ``zkprov/commitment.py`` primitives (``build_merkle_root``,
  ``build_inclusion_proof``, ``MerkleInclusionProof``). Poseidon silently falls
  back to SHA-256 when the ``poseidon-hash`` package is absent, so the
  commitment records the hash that *actually ran*
  (:func:`merkle_hash_algorithm_in_use`). ``build_merkle_root`` rejects empty
  input, so the empty epoch ("zero sealed facts") has an explicit sentinel
  representation that never calls it.
* **Non-membership = adjacency**: for an absent key k, inclusion proofs for the
  neighbouring leaves k1 < k < k2 at adjacent indices, or a boundary proof at
  the first/last leaf. The verifier checks both inclusions against the
  committed root, index adjacency, and key order.
* **Sortedness commitment**: adjacency is sound only if the committed leaves
  really are sorted and duplicate-free. That property carries NO ZK proof here
  — it is committed (``sorted_keys_sha256``) and auditable by full rebuild
  (:func:`verify_epoch_commitment` over the records). A relying party that has
  not audited sortedness holds a proof that is sound *conditional on* the
  producer's sorted construction. The certificate says this in words.
* **Count-conservation predicate** (ROADMAP.md L3, verbatim identity):
  ``attempts = permits + abstains + forbids + errors`` per epoch. The
  right-hand side is computed from sealed DECISION facts only; the left-hand
  side has NO live source today (sealing happens only after a verdict,
  pdp.py:490 — crashes and non-PDP traffic are never counted), so the
  predicate is real code whose ``n_attempts`` input is gated on the hook.
* **Anchoring caveat (a reviewer attacks this first)**: omission detection
  compares a rebuilt epoch against the *original* commitment — which the
  relying party must hold from outside the adversary's control (obtained
  before the attack, or published out-of-band). Nothing durable anchors an
  ``EpochCommitment`` today: the ledger it summarizes is in-memory, and this
  module does not seal commitments back into the ledger (doing so would
  change the epoch it commits to — that re-anchoring design belongs to the
  interchange/witness track, not here). Detection is real *given* an
  honestly-held commitment; it is not magic against an adversary who also
  controls every copy of the commitment.

Design alternative considered and rejected (depth rule, CLAUDE.md)
------------------------------------------------------------------
A bitwise **sparse Merkle tree over the full 2^256 key space** (non-membership
= inclusion proof of the empty leaf at K's path) was the genuinely distinct
second design — differing in data structure (fixed-shape trie vs sorted list)
and trust assumption (it needs no sortedness commitment at all, which is its
real advantage). Rejected for this leap because (a) ROADMAP.md's L3 row — the
boundary for this track — specifies a *sorted-key accumulator* verbatim;
(b) COORDINATION.md's row has this module reusing ``zkprov/commitment.py``,
whose index-authenticated ``MerkleInclusionProof.verify`` is exactly the
binding adjacency needs, whereas an SMT shares none of that tested code and
adds ~256-level default-node-cache machinery as fresh unaudited surface; and
(c) the sortedness gap the SMT closes is honestly disclosed here and closable
by rebuild-audit. Revisit the SMT if the North-Star Module-SIS accumulator
track (ROADMAP.md — `speculative`, out of scope here) ever lands.

ATTEMPT-SEALING HOOK — LANDED (provenance/attempt_seal.py)
----------------------------------------------------------
This section was the L3 scoping doc for the **seam track**; the seam track
landed the hook against it. What stands today, with the two deliberately
open decisions now DECLARED in the hook's own contract
(``attempt_seal.py`` module docstring is the authority):

* ``seal_attempt`` seals one ``SealedFact(ATTEMPT)`` at evaluate() entry
  (between ``pipeline_start`` and the deterministic gate — the only point
  every evaluation passes exactly once), reusing the ``_decision_ledger``
  slot, mirroring ``seal_decision``'s fail-closed contract exactly.
* **Count scoping (decided): gate evaluations COUNT as attempts.** The
  identity is global and symmetric — L5 reflexive gate evaluations seal one
  ATTEMPT and one verdict-keyed DECISION each and balance; fast-paths never
  call evaluate() and produce neither fact.
* **n_error (decided): derivable and ONE-SIDED.** No error-outcome fact is
  sealed; error := ATTEMPT with no matching verdict-keyed DECISION. The
  identity catches missing/fabricated DECISIONs (the omission attack); a
  mid-pipeline death is indistinguishable from an omission — both surface
  as GATED-BROKEN, failing closed.
* **What flipped at landing**: :data:`ATTEMPT_HOOK_PRESENT` is True
  (codebase-level); ``check_count_conservation`` derives ``n_attempts``
  from sealed ATTEMPT facts whenever the epoch holds any (a contradicting
  supplied count is itself GATED-BROKEN); certificates carry
  ``attempt_hook_present``/``complete=True`` *only for the
  count-conservation dimension and only on EPOCH-level evidence* (derived
  source) — pre-hook epochs honestly stay incomplete, and the verifier
  rejects hook-present claims whose conservation shows no derived source.

* **Honest residual blind spot (unchanged by the landing)**: an entry-hook
  bounds, but does not eliminate, uncounted work — anything that dies before
  evaluate() is entered (transport layer, non-PDP traffic) remains
  invisible. The hook turns ``n_attempts`` from trust-me into
  sealed-at-entry; it does not make it total. Reflexive fast-paths (the
  saves/denials before governor.py's gate calls evaluate()) consistently
  produce neither an ATTEMPT nor a DECISION fact, so the identity stays
  balanced on both sides of that boundary.

Maturity
--------
``research_early`` (ROADMAP wave-class "research-grade"; the nearest
``EvidenceMaturity`` member is ``RESEARCH_EARLY`` — there is no
"research_grade" member and this module does not invent one). The crypto
half is real and tested; the conservation claim is now GATED on sealed
ATTEMPT facts for epochs the hook ran over — scoped to the
count-conservation dimension, one-sided per the declared n_error contract,
and still bounded by the residual blind spot above. The hook itself is
``research-solid`` plumbing (live ECDSA-P256 + hash chain); this module's
certificate claims inherit ``research_early``.
"""

from __future__ import annotations

import bisect
import hashlib
import json
import struct
from dataclasses import dataclass, field
from typing import Any, Literal, Sequence

from tex.domain.evidence import EvidenceMaturity
from tex.provenance.models import SealedFact, SealedFactKind, SealedFactRecord
from tex.zkprov.commitment import (
    MerkleInclusionProof,
    build_inclusion_proof,
    build_merkle_root,
    merkle_hash_algorithm_in_use,
)

__all__ = [
    "ATTEMPT_HOOK_PRESENT",
    "EMPTY_EPOCH_SENTINEL",
    "FORBIDDEN_UNQUALIFIED_PHRASES",
    "ConservationCheck",
    "DuplicateKeyError",
    "EpochAccumulator",
    "EpochCommitment",
    "KeyPresentError",
    "NegativeKnowledgeCertificate",
    "NonMembershipProof",
    "VerificationResult",
    "build_epoch_accumulator",
    "check_count_conservation",
    "issue_certificate_with_records",
    "recompute_key",
    "verify_certificate",
    "verify_epoch_commitment",
]

# The upstream attempt-sealing hook EXISTS: provenance/attempt_seal.py seals
# one SealedFact(ATTEMPT) at PolicyDecisionPoint.evaluate() entry (the call
# sits between pipeline_start and the deterministic gate in engine/pdp.py),
# verified live by tests/test_attempt_seal.py before this flip. This constant
# is a CODEBASE-level fact; certificates additionally require EPOCH-level
# evidence — a cert claims attempt_hook_present/complete only when its own
# conservation check derived n_attempts from sealed ATTEMPT facts in the
# epoch (pre-hook epochs and non-PDP ledgers stay incomplete, honestly).
ATTEMPT_HOOK_PRESENT: bool = True

# Explicit representation of the empty epoch ("zero sealed facts"). The
# reused primitive build_merkle_root REJECTS empty input by design, so the
# empty epoch never reaches it; this domain-separated sentinel stands in for
# both roots. Non-membership over an empty epoch is trivially true and
# certified VACUOUS — it says nothing about behaviour.
EMPTY_EPOCH_SENTINEL: str = hashlib.sha256(
    b"tex/negative-knowledge/empty-epoch-v1"
).hexdigest()

# Vocabulary this module's public claims must never use unqualified. The
# certificate proves non-membership in a hash-chained, in-memory, opt-in
# sealed epoch — phrases like "never saw" or the ROADMAP nickname
# "provable ignorance" claim an epistemic totality the construction does
# NOT have. tests/test_negative_knowledge.py pins this.
FORBIDDEN_UNQUALIFIED_PHRASES: tuple[str, ...] = (
    "never saw",
    "provable ignorance",
)

_MATURITY = EvidenceMaturity.RESEARCH_EARLY


class DuplicateKeyError(ValueError):
    """Two epoch records share a payload_sha256 — the sorted-unique invariant
    adjacency soundness needs is violated; the accumulator refuses to build."""


class KeyPresentError(ValueError):
    """A non-membership certificate was requested for a key that IS sealed in
    the epoch. Issuance refuses; the truthful object would be a membership
    proof, not this certificate."""


def _stable_json(obj: Any) -> str:
    # Byte-for-byte mirror of provenance/ledger.py:_stable_json so keys are
    # independently recomputable without importing a private helper.
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str)


def recompute_key(fact: SealedFact) -> str:
    """Recompute the canonical key for a fact from first principles.

    Mirrors the ledger's own payload hashing (ledger.py:289-291 on append,
    re-derived at ledger.py:341 in verify_chain): SHA-256 over the stable
    JSON of ``fact.canonical_payload()``. An auditor uses this instead of
    trusting the stored ``payload_sha256`` field.
    """
    return hashlib.sha256(
        _stable_json(fact.canonical_payload()).encode("utf-8")
    ).hexdigest()


def _key_leaf_bytes(key: str) -> bytes:
    # Leaf record bytes for the Merkle primitives. Keys are fixed-width
    # lowercase hex, so lexicographic byte order == numeric order.
    return key.encode("ascii")


def _normalize_key(key: str) -> str:
    key = key.strip().lower()
    if len(key) != 64 or any(c not in "0123456789abcdef" for c in key):
        raise ValueError("key must be a 64-char lowercase hex sha256 digest")
    return key


def _sorted_keys_commitment(keys: Sequence[str]) -> str:
    """Commitment to the exact sorted key sequence (count-binding via length
    prefix, order-binding via concatenation order). Recomputable by any
    auditor holding the records; this is the sortedness commitment the
    adjacency verifier's soundness is conditional on."""
    h = hashlib.sha256()
    h.update(b"tex/negative-knowledge/sorted-keys-v1\x00")
    h.update(struct.pack(">Q", len(keys)))
    for k in keys:
        h.update(_key_leaf_bytes(k))
    return h.hexdigest()


# --------------------------------------------------------------------------- #
# Epoch accumulator                                                           #
# --------------------------------------------------------------------------- #

@dataclass(frozen=True, slots=True)
class EpochCommitment:
    """The small public commitment to one sealed-ledger epoch.

    ``accumulator_root`` / ``audit_root`` are the sorted-leaf Merkle roots
    from ``zkprov.commitment.build_merkle_root`` (or ``EMPTY_EPOCH_SENTINEL``
    for the zero-record epoch). ``hash_backend`` records the hash that
    ACTUALLY ran when the root was built — Poseidon silently falls back to
    SHA-256 when the ``poseidon-hash`` package is absent, and a commitment
    that hides which one bound the leaves would be a small lie.
    """

    record_count: int
    epoch_head_hash: str | None  # last record_hash in the chain; binds epoch
    accumulator_root: str        # poseidon-or-fallback root (EMPTY sentinel if n=0)
    audit_root: str              # sha256 audit root (EMPTY sentinel if n=0)
    sorted_keys_sha256: str      # sortedness commitment (defined for n=0 too)
    hash_backend: str            # merkle_hash_algorithm_in_use() at build time

    @property
    def is_empty(self) -> bool:
        return self.record_count == 0


@dataclass(frozen=True, slots=True)
class EpochAccumulator:
    """Builder view of one epoch: the sorted-unique keys plus the public
    commitment. Holds enough to construct proofs; the commitment alone is
    what a relying party needs to verify them."""

    commitment: EpochCommitment
    sorted_keys: tuple[str, ...]

    def contains(self, key: str) -> bool:
        return _normalize_key(key) in self.sorted_keys


def build_epoch_accumulator(
    records: Sequence[SealedFactRecord],
) -> EpochAccumulator:
    """Sort the epoch's canonical keys and Merkle-commit them.

    The ledger does not maintain sorted order — this constructs it. Keys are
    recomputed from each fact's canonical payload (never trusted from the
    stored field). Duplicate keys raise :class:`DuplicateKeyError` because
    adjacency soundness requires strictly increasing leaves.

    The empty epoch never touches ``build_merkle_root`` (which rejects empty
    input); it gets the explicit :data:`EMPTY_EPOCH_SENTINEL` representation.
    """
    keys = sorted(recompute_key(rec.fact) for rec in records)
    for a, b in zip(keys, keys[1:]):
        if a == b:
            raise DuplicateKeyError(
                f"duplicate canonical key {a} — two records share a payload"
            )

    head_hash = records[-1].record_hash if records else None
    backend = merkle_hash_algorithm_in_use()

    if not keys:
        commitment = EpochCommitment(
            record_count=0,
            epoch_head_hash=head_hash,
            accumulator_root=EMPTY_EPOCH_SENTINEL,
            audit_root=EMPTY_EPOCH_SENTINEL,
            sorted_keys_sha256=_sorted_keys_commitment(()),
            hash_backend=backend,
        )
        return EpochAccumulator(commitment=commitment, sorted_keys=())

    leaves = tuple(_key_leaf_bytes(k) for k in keys)
    poseidon_root, audit_root = build_merkle_root(leaves)
    commitment = EpochCommitment(
        record_count=len(keys),
        epoch_head_hash=head_hash,
        accumulator_root=poseidon_root,
        audit_root=audit_root,
        sorted_keys_sha256=_sorted_keys_commitment(keys),
        hash_backend=backend,
    )
    return EpochAccumulator(commitment=commitment, sorted_keys=tuple(keys))


def verify_epoch_commitment(
    records: Sequence[SealedFactRecord],
    commitment: EpochCommitment,
) -> "VerificationResult":
    """Full rebuild-audit of a commitment against the actual records.

    This is the check that discharges the sortedness assumption: it
    recomputes every key from canonical payloads, re-sorts, rebuilds both
    roots and the sorted-keys commitment, and compares field by field. Run
    it with the same hash backend the producer used — a backend mismatch is
    reported as such rather than as silent tamper.
    """
    backend_now = merkle_hash_algorithm_in_use()
    if backend_now != commitment.hash_backend:
        return VerificationResult(
            ok=False,
            reason=(
                f"hash backend mismatch: commitment built with "
                f"{commitment.hash_backend!r}, this process runs "
                f"{backend_now!r} — roots are not comparable"
            ),
        )
    try:
        rebuilt = build_epoch_accumulator(records)
    except DuplicateKeyError as exc:
        return VerificationResult(ok=False, reason=str(exc))
    if rebuilt.commitment != commitment:
        return VerificationResult(
            ok=False,
            reason="rebuilt commitment differs — records do not match the "
                   "sealed epoch (omission, addition, or tamper)",
        )
    return VerificationResult(ok=True, reason="rebuild matches commitment")


# --------------------------------------------------------------------------- #
# Non-membership proof (adjacency)                                            #
# --------------------------------------------------------------------------- #

@dataclass(frozen=True, slots=True)
class NonMembershipProof:
    """Adjacency evidence that key k is absent from the committed sorted
    leaves. One of four shapes:

    * ``empty``         — the epoch has zero records (vacuously absent).
    * ``boundary_low``  — k < first leaf; inclusion proof of leaf 0.
    * ``boundary_high`` — k > last leaf; inclusion proof of leaf n-1.
    * ``interior``      — left_key < k < right_key at adjacent indices i, i+1;
                          inclusion proofs for both.

    Soundness is conditional on the sortedness commitment (see module
    docstring); :func:`verify_epoch_commitment` discharges that condition.
    """

    kind: Literal["empty", "boundary_low", "boundary_high", "interior"]
    left_key: str | None = None
    right_key: str | None = None
    left_proof: MerkleInclusionProof | None = None
    right_proof: MerkleInclusionProof | None = None


def _prove_non_membership(
    accumulator: EpochAccumulator, key: str
) -> NonMembershipProof:
    keys = accumulator.sorted_keys
    if not keys:
        return NonMembershipProof(kind="empty")
    if key in keys:
        raise KeyPresentError(
            f"key {key} IS sealed in this epoch — non-membership is false"
        )

    leaves = tuple(_key_leaf_bytes(k) for k in keys)
    # Insertion point separating strictly-smaller from strictly-larger leaves
    # (the key is absent, so no equal leaf exists).
    pos = bisect.bisect_left(keys, key)
    if pos == 0:
        return NonMembershipProof(
            kind="boundary_low",
            right_key=keys[0],
            right_proof=build_inclusion_proof(leaves, 0),
        )
    if pos == len(keys):
        return NonMembershipProof(
            kind="boundary_high",
            left_key=keys[-1],
            left_proof=build_inclusion_proof(leaves, len(keys) - 1),
        )
    return NonMembershipProof(
        kind="interior",
        left_key=keys[pos - 1],
        right_key=keys[pos],
        left_proof=build_inclusion_proof(leaves, pos - 1),
        right_proof=build_inclusion_proof(leaves, pos),
    )


def _verify_non_membership(
    key: str,
    proof: NonMembershipProof,
    commitment: EpochCommitment,
) -> "VerificationResult":
    """Check a non-membership proof against the epoch commitment.

    Verifies inclusion of the neighbour leaves against the committed root,
    index adjacency, and key order. Sound conditional on the committed
    leaves being sorted-unique (auditable via verify_epoch_commitment).
    """
    n = commitment.record_count

    if proof.kind == "empty":
        if n != 0:
            return VerificationResult(
                ok=False, reason="empty-epoch proof against non-empty commitment"
            )
        return VerificationResult(
            ok=True,
            reason="epoch is empty — non-membership vacuously true; this "
                   "certifies nothing about behaviour",
        )
    if n == 0:
        return VerificationResult(
            ok=False, reason="non-empty proof shape against empty commitment"
        )

    def _check_inclusion(
        side: str, k: str | None, p: MerkleInclusionProof | None, index: int
    ) -> str | None:
        if k is None or p is None:
            return f"{side} neighbour missing"
        if p.poseidon_root != commitment.accumulator_root:
            return f"{side} proof bound to a different root"
        if p.leaf_index != index:
            return f"{side} proof at index {p.leaf_index}, expected {index}"
        if not p.verify(_key_leaf_bytes(k)):
            return f"{side} inclusion proof failed"
        return None

    if proof.kind == "boundary_low":
        err = _check_inclusion("right", proof.right_key, proof.right_proof, 0)
        if err:
            return VerificationResult(ok=False, reason=err)
        if not key < proof.right_key:  # type: ignore[operator]
            return VerificationResult(
                ok=False, reason="key not strictly below the first leaf"
            )
        return VerificationResult(
            ok=True,
            reason="absent below first leaf (conditional on the sortedness "
                   "commitment — audit via verify_epoch_commitment)",
        )

    if proof.kind == "boundary_high":
        err = _check_inclusion("left", proof.left_key, proof.left_proof, n - 1)
        if err:
            return VerificationResult(ok=False, reason=err)
        if not key > proof.left_key:  # type: ignore[operator]
            return VerificationResult(
                ok=False, reason="key not strictly above the last leaf"
            )
        return VerificationResult(
            ok=True,
            reason="absent above last leaf (conditional on the sortedness "
                   "commitment — audit via verify_epoch_commitment)",
        )

    if proof.kind == "interior":
        if proof.left_proof is None or proof.right_proof is None:
            return VerificationResult(ok=False, reason="neighbour proof missing")
        i = proof.left_proof.leaf_index
        if proof.right_proof.leaf_index != i + 1:
            return VerificationResult(
                ok=False,
                reason="neighbour leaves are not at adjacent indices",
            )
        err = _check_inclusion("left", proof.left_key, proof.left_proof, i)
        if err:
            return VerificationResult(ok=False, reason=err)
        err = _check_inclusion(
            "right", proof.right_key, proof.right_proof, i + 1
        )
        if err:
            return VerificationResult(ok=False, reason=err)
        if not (proof.left_key < key < proof.right_key):  # type: ignore[operator]
            return VerificationResult(
                ok=False, reason="key not strictly between adjacent leaves"
            )
        return VerificationResult(
            ok=True,
            reason="absent between adjacent leaves (conditional on the "
                   "sortedness commitment — audit via verify_epoch_commitment)",
        )

    return VerificationResult(ok=False, reason=f"unknown proof kind {proof.kind!r}")


# --------------------------------------------------------------------------- #
# Count-conservation predicate                                                #
# --------------------------------------------------------------------------- #

@dataclass(frozen=True, slots=True)
class ConservationCheck:
    """Result of the count-conservation identity
    ``attempts == permits + abstains + forbids + errors`` over one epoch.

    ``status`` is three-valued on purpose:

    * ``UNGATED``      — no sealed source for ``n_attempts`` exists (the
                         attempt-sealing hook is absent), so the identity was
                         NOT evaluated. ``holds is None`` — this must never be
                         collapsed to "holds".
    * ``GATED-HOLDS``  — counts supplied (by the future hook, or a test
                         standing in for it) and the identity holds.
    * ``GATED-BROKEN`` — counts supplied and the identity FAILS: the epoch's
                         verdict records do not account for the attempts —
                         the omission-attack alarm.
    """

    status: Literal["UNGATED", "GATED-HOLDS", "GATED-BROKEN"]
    holds: bool | None
    n_attempts: int | None
    n_permit: int
    n_abstain: int
    n_forbid: int
    n_error: int | None
    note: str
    # Where n_attempts came from: "derived" (counted from sealed ATTEMPT
    # facts in the epoch — the only source that can support a completeness
    # claim), "supplied" (externally provided, trust-me — pre-hook epochs),
    # or None (UNGATED). The verifier keys on this field.
    attempts_source: Literal["derived", "supplied"] | None = None


def check_count_conservation(
    records: Sequence[SealedFactRecord],
    *,
    n_attempts: int | None = None,
    n_error: int | None = None,
) -> ConservationCheck:
    """Evaluate ``attempts == permits + abstains + forbids + errors`` over the
    epoch's sealed facts.

    Both sides now come from records actually in the chain: the right-hand
    side from verdict-keyed DECISION facts, and — since the attempt hook
    landed (provenance/attempt_seal.py, sealed at evaluate() entry) — the
    left-hand side from ATTEMPT facts. When the epoch holds ATTEMPT facts
    they ARE ``n_attempts`` (``attempts_source="derived"``); a supplied
    ``n_attempts`` that contradicts the sealed count is the fabrication
    alarm and returns GATED-BROKEN. Epochs with no ATTEMPT facts (sealed
    before the hook, or by a non-PDP producer) fall back to the supplied
    value (``attempts_source="supplied"``, trust-me) or UNGATED
    (``holds=None``), never a vacuous pass.

    The identity is ONE-SIDED by the hook's declared n_error contract: no
    error-outcome fact is sealed, so an attempt with no matching verdict —
    an omitted/fabricated DECISION or a mid-pipeline death alike — surfaces
    as GATED-BROKEN; the two causes are indistinguishable here, and work
    dying before evaluate() entry is never counted at all. ``n_error``
    remains an external input; when omitted while gated it is treated as 0
    and the note says so.
    """
    n_permit = n_abstain = n_forbid = 0
    n_attempt_facts = 0
    for rec in records:
        if rec.fact.kind is SealedFactKind.ATTEMPT:
            n_attempt_facts += 1
            continue
        if rec.fact.kind is not SealedFactKind.DECISION:
            continue
        verdict = rec.fact.detail.get("verdict")
        if verdict == "PERMIT":
            n_permit += 1
        elif verdict == "ABSTAIN":
            n_abstain += 1
        elif verdict == "FORBID":
            n_forbid += 1

    attempts_source: Literal["derived", "supplied"] | None
    if n_attempt_facts > 0:
        attempts_source = "derived"
        if n_attempts is not None and n_attempts != n_attempt_facts:
            return ConservationCheck(
                status="GATED-BROKEN",
                holds=False,
                n_attempts=n_attempt_facts,
                n_permit=n_permit,
                n_abstain=n_abstain,
                n_forbid=n_forbid,
                n_error=n_error,
                note=(
                    f"supplied n_attempts={n_attempts} contradicts the "
                    f"{n_attempt_facts} sealed ATTEMPT facts in the epoch — "
                    "the sealed facts are the only honest source; a "
                    "conflicting external count is itself the alarm"
                ),
                attempts_source=attempts_source,
            )
        n_attempts = n_attempt_facts
        source_note = f" (n_attempts derived from {n_attempt_facts} sealed ATTEMPT facts)"
    elif n_attempts is not None:
        attempts_source = "supplied"
        source_note = (
            " (n_attempts externally supplied — trust-me; this epoch holds "
            "no sealed ATTEMPT facts)"
        )
    else:
        return ConservationCheck(
            status="UNGATED",
            holds=None,
            n_attempts=None,
            n_permit=n_permit,
            n_abstain=n_abstain,
            n_forbid=n_forbid,
            n_error=n_error,
            note=(
                "no sealed ATTEMPT facts in this epoch and n_attempts not "
                "supplied; identity NOT evaluated (UNGATED is not HOLDS) — "
                "the hook exists but did not run over these records "
                "(pre-hook epoch, or a non-PDP ledger)"
            ),
            attempts_source=None,
        )

    err = 0 if n_error is None else n_error
    rhs = n_permit + n_abstain + n_forbid + err
    holds = n_attempts == rhs
    note = (
        f"gated check: {n_attempts} attempts vs {n_permit}+{n_abstain}+"
        f"{n_forbid}+{err} = {rhs}"
    )
    note += source_note
    if n_error is None:
        note += (
            " (n_error unsupplied, counted as 0 — no error seal exists by "
            "the hook's declared one-sided contract)"
        )
    return ConservationCheck(
        status="GATED-HOLDS" if holds else "GATED-BROKEN",
        holds=holds,
        n_attempts=n_attempts,
        n_permit=n_permit,
        n_abstain=n_abstain,
        n_forbid=n_forbid,
        n_error=n_error,
        note=note,
        attempts_source=attempts_source,
    )


# --------------------------------------------------------------------------- #
# The certificate                                                             #
# --------------------------------------------------------------------------- #

@dataclass(frozen=True, slots=True)
class VerificationResult:
    ok: bool
    reason: str


@dataclass(frozen=True, slots=True)
class NegativeKnowledgeCertificate:
    """A non-membership certificate over one sealed ledger epoch.

    Claims exactly: "no sealed fact with key ``key`` exists in the epoch
    committed by ``commitment``" — scoped, in-memory, opt-in.
    The honesty pins are first-class fields, not prose:

    * ``complete`` / ``attempt_hook_present`` — EPOCH-level claims, True only
      when this epoch's conservation check derived ``n_attempts`` from sealed
      ATTEMPT facts (the attempt hook ran over these records). ``complete``
      is scoped to the COUNT-CONSERVATION dimension only — the entry hook
      bounds, never eliminates, uncounted work. Defaults stay False so a
      hand-built certificate under-claims rather than over-claims.
    * ``vacuous`` — True when the epoch holds zero sealed facts (including
      every unsealed deployment, where TEX_SEAL_DECISIONS is unset).
    * ``ledger_in_memory`` / ``ledger_opt_in`` — structural facts of today's
      ledger (ledger.py:256; main.py seal_decisions block): a restart erases
      the epoch, and most deployments seal nothing.
    * ``hash_backend`` — the Merkle hash that actually ran.
    """

    key: str
    commitment: EpochCommitment
    proof: NonMembershipProof
    conservation: ConservationCheck
    claim_text: str
    vacuous: bool
    hash_backend: str
    complete: bool = False
    attempt_hook_present: bool = False
    ledger_in_memory: bool = True
    ledger_opt_in: bool = True
    maturity: str = field(default=_MATURITY.value)


def _claim_text(
    key: str, commitment: EpochCommitment, conservation: ConservationCheck
) -> str:
    head = commitment.epoch_head_hash or "none"
    base = (
        f"no sealed fact with key {key} exists in THIS ledger epoch "
        f"(head={head}, records={commitment.record_count}, "
        f"hash={commitment.hash_backend}). Scope: a hash-chained, in-memory, "
        f"opt-in sealed epoch — erased on restart, empty unless "
        f"TEX_SEAL_DECISIONS=1."
    )
    if conservation.attempts_source == "derived":
        base += (
            f" Completeness is claimed for the COUNT-CONSERVATION dimension "
            f"only: the attempt-sealing hook sealed "
            f"{conservation.n_attempts} ATTEMPT fact(s) at evaluate() entry "
            f"in this epoch. The identity is ONE-SIDED — an omitted DECISION "
            f"and a mid-pipeline death are indistinguishable (both surface "
            f"as GATED-BROKEN) — and work dying before evaluate() entry "
            f"remains invisible."
        )
    else:
        base += (
            " Completeness is NOT claimed: no ATTEMPT facts are sealed in "
            "this epoch, so unsealed attempts are invisible to this "
            "certificate."
        )
    if commitment.record_count == 0:
        base += (
            " The epoch contains ZERO sealed facts: non-membership is "
            "vacuously true and certifies nothing about behaviour."
        )
    return base


def issue_certificate_with_records(
    records: Sequence[SealedFactRecord],
    key: str,
    *,
    n_attempts: int | None = None,
    n_error: int | None = None,
) -> NegativeKnowledgeCertificate:
    """Build the accumulator from ``records`` and issue a non-membership
    certificate whose conservation check is computed over those same records.

    Raises :class:`KeyPresentError` when the key IS sealed in the epoch —
    the certificate cannot be issued for a present key. ``n_attempts`` is
    derived from sealed ATTEMPT facts when the epoch holds any (a supplied
    value that contradicts them yields GATED-BROKEN); for pre-hook epochs it
    remains an optional trust-me pass-through; omitted → UNGATED.

    ``attempt_hook_present`` / ``complete`` are set from EPOCH-level
    evidence: True only when conservation derived its count from sealed
    ATTEMPT facts. The codebase-level :data:`ATTEMPT_HOOK_PRESENT` alone is
    never enough — a hook that exists but did not run over these records
    supports no completeness claim.
    """
    key = _normalize_key(key)
    accumulator = build_epoch_accumulator(records)
    proof = _prove_non_membership(accumulator, key)
    conservation = check_count_conservation(
        records, n_attempts=n_attempts, n_error=n_error
    )
    commitment = accumulator.commitment
    hook_ran = (
        ATTEMPT_HOOK_PRESENT and conservation.attempts_source == "derived"
    )
    return NegativeKnowledgeCertificate(
        key=key,
        commitment=commitment,
        proof=proof,
        conservation=conservation,
        claim_text=_claim_text(key, commitment, conservation),
        vacuous=commitment.is_empty,
        hash_backend=commitment.hash_backend,
        complete=hook_ran,
        attempt_hook_present=hook_ran,
    )


def verify_certificate(
    cert: NegativeKnowledgeCertificate,
) -> VerificationResult:
    """Offline check of a certificate against its own commitment.

    Verifies the adjacency proof (inclusions, adjacency, order) and the
    honesty pins — over-claiming is a verification failure here, not a
    style issue. A hook-present / complete claim is accepted ONLY when the
    certificate's own conservation check shows the hook ran over this epoch
    (``attempts_source == "derived"`` from sealed ATTEMPT facts); claimed
    without that evidence it is REJECTED in both forms. Honest limit: these
    fields are internal-consistency checks over the certificate object —
    a conservation block fabricated wholesale is caught only at the records
    level (``verify_epoch_commitment``), same trust shape as every other
    cert field. Does NOT re-audit sortedness — that needs the records
    (verify_epoch_commitment).
    """
    hook_evidence = (
        cert.conservation.attempts_source == "derived"
        and cert.conservation.status != "UNGATED"
        and (cert.conservation.n_attempts or 0) > 0
    )
    if cert.attempt_hook_present and not hook_evidence:
        return VerificationResult(
            ok=False,
            reason="certificate claims the attempt-sealing hook ran over "
                   "this epoch, but its conservation check shows no sealed "
                   "ATTEMPT source (n_attempts not derived) — over-claim "
                   "rejected",
        )
    if cert.complete and not cert.attempt_hook_present:
        return VerificationResult(
            ok=False,
            reason="certificate claims complete=True without "
                   "attempt_hook_present — over-claim rejected",
        )
    if cert.commitment.is_empty and not cert.vacuous:
        return VerificationResult(
            ok=False,
            reason="empty epoch not marked vacuous — over-claim rejected",
        )
    if cert.conservation.status == "UNGATED" and cert.conservation.holds is not None:
        return VerificationResult(
            ok=False,
            reason="UNGATED conservation must carry holds=None — a vacuous "
                   "pass was fabricated",
        )
    for phrase in FORBIDDEN_UNQUALIFIED_PHRASES:
        if phrase in cert.claim_text.lower():
            return VerificationResult(
                ok=False,
                reason=f"claim text uses forbidden vocabulary {phrase!r}",
            )
    try:
        key = _normalize_key(cert.key)
    except ValueError as exc:
        return VerificationResult(ok=False, reason=str(exc))
    if cert.hash_backend != cert.commitment.hash_backend:
        return VerificationResult(
            ok=False, reason="certificate/commitment hash backend mismatch"
        )
    # Inclusion proofs are recomputed with THIS process's hash backend; a
    # cross-backend verification would fail closed but with a misleading
    # "inclusion proof failed" — name the real cause instead.
    backend_now = merkle_hash_algorithm_in_use()
    if not cert.commitment.is_empty and backend_now != cert.hash_backend:
        return VerificationResult(
            ok=False,
            reason=(
                f"hash backend mismatch: certificate built with "
                f"{cert.hash_backend!r}, this process runs {backend_now!r} — "
                f"proofs are not checkable here"
            ),
        )
    return _verify_non_membership(key, cert.proof, cert.commitment)
