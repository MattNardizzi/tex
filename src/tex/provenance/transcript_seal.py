"""
Verdict-transcript sealing seam — seal one ``SealedFact(VERDICT_TRANSCRIPT)`` per
verdict: the canonical execution transcript's hash + its monotonicity witness.

This is the durable, offline-verifiable half of the night-run transcript work
(``engine/verdict_transcript.py``). The PDP builds a canonical, hashable
execution transcript for every verdict and derives a monotonicity witness; this
module seals the transcript HASH (the commitment a future zk-Verdict circuit and
the self-certifying offline checker attest) together with the witness (the
relation: signals only lowered the verdict, and the structural floor forced
FORBID) into the hash-chained, ECDSA-P256-signed ``SealedFactLedger``.

It is the proof-carrying-verdict substrate: the sealed fact is a Proof-Carrying
Verdict Record whose ``detail`` is self-contained — it embeds the full canonical
transcript and witness — so the ``night/offline-checker`` thread can reconstruct
the transcript, recompute the witness with
``verify_transcript_witness`` and re-confirm the invariants held, from the sealed
bytes alone, holding only Tex's public key.

Honesty — what the seal proves and what it does NOT:
  * AUTHORSHIP + INTEGRITY only. The ledger's hash CHAIN proves the sealed
    transcript was not reordered/deleted/altered; the per-record ECDSA-P256
    signature proves Tex authored it (live signer is ECDSA-P256, not PQ). The
    seal does NOT prove the transcript faithfully reflects the live run, and it
    does NOT prove the verdict is the correct output of the policy (that is L1 /
    zkPDP). The witness proves a STRUCTURAL property of the *recorded* trace,
    nothing more. The ``claim`` string says all of this in words.
  * Maturity is ``RESEARCH_SOLID``: the seal is real live crypto, but this is a
    newly-wired governance fact, not a CI-benchmarked production default. (The zk
    story the transcript enables is ``speculative`` — see verdict_transcript.py —
    but nothing zk is sealed here; only a SHA-256 commitment + the witness.)

Opt-in, fail-closed, observation-only (mirrors ``decision_seal.seal_decision``):
  * Disabled by default. Two gates must BOTH hold to seal: a ledger is wired AND
    ``TEX_SEAL_VERDICT_TRANSCRIPT`` is truthy in the environment. Default-off is
    deliberate — it keeps this fact OUT of the per-verdict ledger by default
    (every verdict already seals an ATTEMPT + a decision fact; adding a third
    record unconditionally would perturb the exact-sequence ledger census tests
    and double the opt-in ledger growth). A ``VERDICT_TRANSCRIPT`` is a distinct
    kind, so even when enabled it is invisible to the decision-keyed L1/L3
    consumers.
  * ``ledger is None`` or flag-off → zero-cost no-op, returns ``None``.
  * An append failure is logged and returns ``None`` — it never raises into the
    verdict path and never alters the verdict (which is already final).
"""

from __future__ import annotations

import logging
import os

from tex.domain.evidence import EvidenceMaturity
from tex.engine.verdict_transcript import MonotonicityWitness, VerdictTranscript
from tex.provenance.ledger import SealedFactLedger
from tex.provenance.models import SealedFact, SealedFactKind, SealedFactRecord

_logger = logging.getLogger(__name__)

# The opt-in environment switch. Read fresh on every call (not cached at import)
# so a test can flip it with monkeypatch.setenv without reimporting the module.
_ENABLE_ENV = "TEX_SEAL_VERDICT_TRANSCRIPT"
_TRUTHY = frozenset({"1", "true", "yes", "on"})

# The seal mechanism is real live crypto; as a governance fact it is newly wired,
# so it is deliberately NOT ``PRODUCTION``. Same convention as the M0 decision
# fact and the attempt fact.
_TRANSCRIPT_MATURITY = EvidenceMaturity.RESEARCH_SOLID


def transcript_sealing_enabled() -> bool:
    """True iff ``TEX_SEAL_VERDICT_TRANSCRIPT`` is set truthy. The opt-in gate."""
    return os.getenv(_ENABLE_ENV, "").strip().casefold() in _TRUTHY


def build_transcript_fact(
    transcript: VerdictTranscript,
    witness: MonotonicityWitness,
) -> SealedFact:
    """Map a transcript + witness to a canonical ``SealedFact(VERDICT_TRANSCRIPT)``.

    Pure (no I/O, no mutation). The ``detail`` is self-contained — the transcript
    hash (the commitment), the full canonical transcript and witness, plus their
    schema versions and a flat summary — so an offline verifier needs nothing but
    this fact and Tex's public key. The ``claim`` is deliberately narrow: it
    asserts only that the recorded trace + witness were sealed, never that the
    verdict is correct.
    """
    t_hash = transcript.transcript_hash()
    holds = witness.holds
    return SealedFact(
        kind=SealedFactKind.VERDICT_TRANSCRIPT,
        subject_id=transcript.request_id,
        claim=(
            f"canonical verdict transcript {t_hash} sealed for request "
            f"{transcript.request_id} (verdict {transcript.final_verdict.value}); "
            f"monotonicity witness holds={holds} "
            f"(structural_floor_forced_forbid="
            f"{witness.structural_floor_forced_forbid}) — authorship+integrity "
            f"sealed; this proves a structural property of the RECORDED trace, "
            f"not verdict correctness (see L1 zkPDP) and not faithfulness to the "
            f"live run"
        ),
        maturity=_TRANSCRIPT_MATURITY,
        detail={
            # The commitment the prompt requires sealed + the witness alongside it.
            "transcript_hash": t_hash,
            "transcript_schema_version": transcript.schema_version,
            "witness_hash": witness.witness_hash(),
            "witness_schema_version": witness.schema_version,
            # Flat summary for cheap filtering without re-parsing the nested forms.
            "holds": holds,
            "final_verdict": transcript.final_verdict.value,
            "final_risk_score": transcript.final_risk_score,
            "structural_floor_fired": transcript.structural_floor_fired,
            "structural_floor_forced_forbid": witness.structural_floor_forced_forbid,
            "n_stages": witness.n_stages,
            "n_transforming_stages": witness.n_transforming_stages,
            "n_violations": len(witness.violations),
            # Self-contained, offline-recheckable bodies. Canonical payloads so a
            # verifier reconstructs the exact objects and recomputes the hash.
            "transcript": transcript.canonical_payload(),
            "witness": witness.canonical_payload(),
        },
    )


def seal_verdict_transcript(
    ledger: SealedFactLedger | None,
    *,
    transcript: VerdictTranscript,
    witness: MonotonicityWitness,
) -> SealedFactRecord | None:
    """Seal one ``VERDICT_TRANSCRIPT`` fact into ``ledger`` and return its PCVR.

    Opt-in, fail-closed, observation-only:
      * ``ledger is None`` OR ``TEX_SEAL_VERDICT_TRANSCRIPT`` not truthy → no-op,
        return ``None`` (today's behaviour, zero cost).
      * an append failure is logged and returns ``None`` — it never propagates
        into the verdict path and the verdict is unaffected.
    """
    if ledger is None or not transcript_sealing_enabled():
        return None
    try:
        return ledger.append(build_transcript_fact(transcript, witness))
    except Exception:  # pragma: no cover - defensive; a seal must never break a verdict
        _logger.warning(
            "verdict-transcript seal failed for request %s; verdict unaffected, "
            "transcript not sealed",
            getattr(transcript, "request_id", "?"),
            exc_info=True,
        )
        return None


__all__ = [
    "transcript_sealing_enabled",
    "build_transcript_fact",
    "seal_verdict_transcript",
]
