"""Session 3 — the presence binding attestor.

Implements the contract's :class:`~tex.presence.contract.PresenceAttestor`
protocol: for each NON-ABSTAIN :class:`~tex.presence.contract.PresenceVerdict`
it produces a signed :class:`~tex.presence.contract.Attestation` binding
``claim_id → the EvidenceRefs it was checked against → tier`` (plus the spoken
phrasing and the rest of the verdict's material content — see
:mod:`tex.presence.attest.subject`).

It does NOT roll its own crypto. The whole signing substrate is
:class:`tex.evidence.seal.EvidenceChainSigner` (composite ML-DSA-65 + Ed25519
when the backend is present; honest ECDSA-P256 fallback otherwise). The signer's
self-describing block maps 1:1 onto the :class:`Attestation` fields.

Two honesty invariants this module exists to hold
-------------------------------------------------
1. **Algorithm is never assumed.** ``Attestation.algorithm`` /
   ``is_post_quantum`` are read off the algorithm that ACTUALLY produced the
   signature (``block["algorithm"]``), never hard-coded. ``is_post_quantum`` is
   ``"ml-dsa" in algorithm`` — the exact predicate
   ``EvidenceChainSigner.is_post_quantum`` uses — so the label can never drift
   above the real signature.
2. **Sealing is OFF by default.** Gated on ``TEX_SEAL_DECISIONS`` (the same flag
   as the decision ledger). When off, :func:`build_presence_attestor` returns a
   *disabled* attestor — it builds no signer, persists no key, and every
   ``attest`` returns ``None`` so verdicts honestly carry no attestation (the
   contract allows ``attestation=None``).

File-ownership: all new code lives under ``src/tex/presence/attest/``. This module
EXPOSES :func:`build_presence_attestor` (the factory the orchestrator wires into
``main.py`` next to ``presence_brain``, fail-safe OFF) and :func:`apply_attestation`
(the post-step ``compose.py`` calls at integration). Neither ``main.py`` nor
``compose.py`` is edited here.
"""

from __future__ import annotations

import logging
import os
from dataclasses import replace
from typing import Any

from tex.presence.attest.subject import build_attestation_subject
from tex.presence.contract import (
    AnswerEnvelope,
    Attestation,
    PresenceClaim,
    PresenceTier,
    PresenceVerdict,
)

_logger = logging.getLogger(__name__)

__all__ = ["PresenceBindingAttestor", "build_presence_attestor", "apply_attestation"]

# Same flag, same parse shape as the M0 decision ledger (main.py:876) so a single
# operator switch governs all decision/attestation sealing.
_SEAL_FLAG = "TEX_SEAL_DECISIONS"
_TRUTHY = {"1", "true", "yes"}

# Dedicated key location for the presence attestation identity, kept separate from
# the evidence-chain seal key (``var/tex/keys/evidence_seal_key.json``) so the
# presence signing key can be pinned and rotated independently by a relying party.
_DEFAULT_KEY_DIR = "var/tex/keys/presence"
_DEFAULT_KEY_ID = "presence-attest-key-v1"


def _is_post_quantum(algorithm_value: str) -> bool:
    """PQ iff an ML-DSA component is present — identical predicate to
    ``EvidenceChainSigner.is_post_quantum``, applied to the algorithm that
    actually signed THIS attestation."""
    return "ml-dsa" in algorithm_value


class PresenceBindingAttestor:
    """Signs the (claim → evidence → tier) binding with the evidence-chain signer.

    Construct via :func:`build_presence_attestor`. A ``signer`` of ``None`` is the
    sanctioned *disabled* state (sealing off / signer unavailable): ``enabled`` is
    ``False`` and every ``attest`` returns ``None``.
    """

    __slots__ = ("_signer",)

    def __init__(self, signer: Any | None) -> None:
        # signer: tex.evidence.seal.EvidenceChainSigner | None. Typed as Any to
        # keep this module importable without eagerly importing the seal stack.
        self._signer = signer

    @property
    def enabled(self) -> bool:
        """True iff a signer is configured (i.e. sealing is on and a signer built)."""
        return self._signer is not None

    @property
    def algorithm(self) -> str | None:
        """The active signing algorithm, or ``None`` when disabled."""
        return self._signer.algorithm.value if self._signer is not None else None

    @property
    def is_post_quantum(self) -> bool:
        """True iff the active signer is post-quantum. ``False`` when disabled."""
        return bool(self._signer is not None and self._signer.is_post_quantum)

    def attest(self, *, claim: PresenceClaim, verdict: PresenceVerdict) -> Attestation | None:
        """Return a signed :class:`Attestation` for a non-ABSTAIN verdict, or
        ``None``.

        Returns ``None`` when: sealing is disabled (no signer), or the verdict is
        ABSTAIN (nothing was grounded, so there is no binding to attest). Raises
        ``ValueError`` only on a programming error — a claim/verdict id mismatch
        (caught by :func:`apply_attestation` on the hot path).
        """
        if self._signer is None:
            return None
        if verdict.tier is PresenceTier.ABSTAIN:
            return None

        subject = build_attestation_subject(claim, verdict)  # raises on id mismatch
        block = self._signer.sign_payload(subject)

        algorithm = str(block["algorithm"])
        is_pq = _is_post_quantum(algorithm)
        # Defensive honesty: the label derived from the signed algorithm must
        # agree with the signer's own self-report. They are computed the same way,
        # so a mismatch would signal a substrate change — log it, and trust the
        # algorithm that actually signed.
        if is_pq != self._signer.is_post_quantum:
            _logger.warning(
                "presence attest: is_post_quantum(%s)=%s disagrees with signer.is_post_quantum=%s; "
                "trusting the signing algorithm",
                algorithm, is_pq, self._signer.is_post_quantum,
            )

        return Attestation(
            algorithm=algorithm,
            signed_digest_sha256=str(block["signed_digest_sha256"]),
            signature_b64=str(block["signature_b64"]),
            is_post_quantum=is_pq,
            key_id=block.get("key_id"),
            public_key_b64=block.get("public_key_b64"),
            signed_at=block.get("signed_at"),
        )


def build_presence_attestor(
    *,
    enabled: bool | None = None,
    signer: Any | None = None,
    key_dir: str = _DEFAULT_KEY_DIR,
    key_id: str = _DEFAULT_KEY_ID,
) -> PresenceBindingAttestor:
    """Factory the orchestrator wires into ``main.py`` (fail-safe OFF).

    Wiring (next to ``presence_brain``)::

        presence_attestor = build_presence_attestor()  # OFF unless TEX_SEAL_DECISIONS=1

    Behaviour:
      * ``enabled`` defaults to ``TEX_SEAL_DECISIONS`` being truthy. When off,
        returns a disabled attestor WITHOUT building a signer or touching disk —
        a no-op on a default boot.
      * When on and no ``signer`` is injected, builds the real
        :func:`tex.evidence.seal.build_evidence_chain_signer` (which itself never
        raises and falls back to ECDSA-P256, honestly labelled, if no ML-DSA
        backend is present). Any failure fails CLOSED to a disabled attestor —
        never crashes the boot.
      * ``signer`` may be injected (tests / a KMS-backed key).
    """
    if enabled is None:
        enabled = os.environ.get(_SEAL_FLAG, "").strip().lower() in _TRUTHY

    if not enabled:
        return PresenceBindingAttestor(signer=None)

    if signer is None:
        try:
            from tex.evidence.seal import build_evidence_chain_signer

            signer = build_evidence_chain_signer(key_dir=key_dir, key_id=key_id)
        except Exception:  # noqa: BLE001 — fail closed: no attestation beats a crash
            _logger.warning(
                "presence attest: signer build failed; attestation disabled", exc_info=True
            )
            return PresenceBindingAttestor(signer=None)

    return PresenceBindingAttestor(signer=signer)


def _apply_to_verdict(
    verdict: PresenceVerdict, claim: PresenceClaim, attestor: Any
) -> PresenceVerdict:
    """Return ``verdict`` with ``.attestation`` set, or unchanged. Never raises —
    any attestor failure fails closed to no attestation (the contract allows
    ``attestation=None``)."""
    try:
        attestation = attestor.attest(claim=claim, verdict=verdict)
    except Exception:  # noqa: BLE001 — attestation must never break the voice path
        _logger.warning("presence attest: attest() raised; leaving verdict unattested", exc_info=True)
        return verdict
    if attestation is None:
        return verdict
    return replace(verdict, attestation=attestation)


def _apply_to_envelope(envelope: AnswerEnvelope, attestor: Any) -> AnswerEnvelope:
    """Attest every verdict in the envelope, pairing it with its claim by
    ``claim_id`` (the subject needs the claim's ``kind`` and ``text_span``)."""
    claims_by_id = {c.claim_id: c for c in envelope.claims}
    new_verdicts = []
    for v in envelope.verdicts:
        claim = claims_by_id.get(v.claim_id)
        if claim is None:
            # No paired claim → cannot build a subject; leave unattested honestly.
            new_verdicts.append(v)
            continue
        new_verdicts.append(_apply_to_verdict(v, claim, attestor))
    return replace(envelope, verdicts=tuple(new_verdicts))


def apply_attestation(
    target: AnswerEnvelope | PresenceVerdict,
    attestor: Any,
    *,
    claim: PresenceClaim | None = None,
) -> AnswerEnvelope | PresenceVerdict:
    """Return ``target`` with ``.attestation`` set on its non-ABSTAIN verdict(s).

    The post-step ``compose.py`` calls at integration::

        envelope = build_envelope(...)
        envelope = apply_attestation(envelope, presence_attestor)

    Accepts either an :class:`AnswerEnvelope` (the live integration object — pairs
    each verdict with its claim internally) or a single :class:`PresenceVerdict`
    (``claim=`` then required, since a verdict alone lacks the claim's kind/span).

    No-op passthrough when ``attestor`` is ``None`` or disabled, so the wiring is
    safe on a default (sealing-off) boot.
    """
    if attestor is None or not getattr(attestor, "enabled", True):
        return target

    if isinstance(target, AnswerEnvelope):
        return _apply_to_envelope(target, attestor)
    if isinstance(target, PresenceVerdict):
        if claim is None:
            raise ValueError(
                "apply_attestation(PresenceVerdict, ...) requires claim= "
                "(a verdict alone lacks the claim's kind/text_span needed to bind)."
            )
        return _apply_to_verdict(target, claim, attestor)

    raise TypeError(
        f"apply_attestation expects an AnswerEnvelope or PresenceVerdict, got {type(target)!r}"
    )
