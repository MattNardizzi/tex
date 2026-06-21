"""``tex.presence.attest`` — Session 3: proof-carrying grounding attestation.

Binds, for every NON-ABSTAIN :class:`~tex.presence.contract.PresenceVerdict`, the
triple ``claim_id → the EvidenceRefs it was checked against → tier`` into a signed
:class:`~tex.presence.contract.Attestation`, using the real evidence-chain signer
(:mod:`tex.evidence.seal`) — composite ML-DSA-65 + Ed25519 when the post-quantum
backend is present, honest ECDSA-P256 otherwise. The algorithm is ALWAYS read off
the signature that was actually produced; PQ is never assumed. Sealing is OFF
unless ``TEX_SEAL_DECISIONS=1``.

A standalone offline verifier (:func:`verify_attestation`) lets a fresh clone
re-derive the subject, recompute the digest, and verify the signature against a
PINNED public key — proving the binding without trusting Tex.

Public surface
--------------
  * :func:`build_presence_attestor` — the factory the orchestrator wires into
    ``main.py`` next to ``presence_brain`` (fail-safe OFF).
  * :func:`apply_attestation` — the post-step ``compose.py`` calls to set
    ``.attestation`` on an :class:`AnswerEnvelope`'s (or a single verdict's)
    non-ABSTAIN verdict(s).
  * :func:`verify_attestation` / :class:`AttestationVerification` — the offline
    verifier and its honest, fail-closed result.
  * :func:`recompute_row_hash` — recompute a digest-less row's content anchor the
    way the gate sealed it (to build ``resolved_record_hashes`` for anchoring).
  * :func:`build_attestation_subject` / :func:`subject_digest_hex` — the shared
    canonical subject + its digest (used by both signer and verifier).

INTEGRATION (the two additive lines the orchestrator owns; NOT edited here)
---------------------------------------------------------------------------
``main.py`` (next to ``presence_brain``, fail-safe OFF)::

    from tex.presence.attest import build_presence_attestor
    presence_attestor = build_presence_attestor()  # OFF unless TEX_SEAL_DECISIONS=1

``compose.py`` (post-step, after ``build_envelope``)::

    from tex.presence.attest import apply_attestation
    envelope = apply_attestation(envelope, presence_attestor)

Honest edge: this attests the claim→evidence→tier BINDING (tamper-evidence, and
origin-evidence when the key is pinned). It does NOT prove the world is true, does
NOT prove chain-membership/ordering, and is NOT a TEE.
"""

from tex.presence.attest.attestor import (
    PresenceBindingAttestor,
    apply_attestation,
    build_presence_attestor,
)
from tex.presence.attest.subject import (
    SUBJECT_VERSION,
    build_attestation_subject,
    subject_digest_hex,
)
from tex.presence.attest.verify import (
    AttestationVerification,
    recompute_row_hash,
    verify_attestation,
)

__all__ = [
    "PresenceBindingAttestor",
    "build_presence_attestor",
    "apply_attestation",
    "AttestationVerification",
    "verify_attestation",
    "recompute_row_hash",
    "build_attestation_subject",
    "subject_digest_hex",
    "SUBJECT_VERSION",
]
