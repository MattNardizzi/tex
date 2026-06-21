"""Shared fixtures for the presence attestation tests.

Signers are built WITHOUT touching disk or the selfgov governor (a direct
``EvidenceChainSigner`` over a freshly generated keypair) so the tests are fast
and hermetic. The ECDSA signer is always available (no exotic backend); the
post-quantum composite signer is skipped where the ML-DSA backend is absent — the
honesty assertions about the PQ algorithm only make sense when PQ is real.
"""

from __future__ import annotations

import pytest

from tex.presence.attest import build_presence_attestor
from tex.presence.contract import (
    AnswerEnvelope,
    ClaimKind,
    EvidenceRef,
    PresenceClaim,
    PresenceTier,
    PresenceVerdict,
)
from tex.pqcrypto.algorithm_agility import SignatureAlgorithm, get_signature_provider


def _make_signer(algorithm: SignatureAlgorithm):
    """An ``EvidenceChainSigner`` over a fresh keypair — no disk, no governor."""
    from tex.evidence.seal import EvidenceChainSigner

    key = get_signature_provider(algorithm).generate_keypair(f"presence-test-{algorithm.value}")
    return EvidenceChainSigner(key=key)


@pytest.fixture()
def ecdsa_signer():
    return _make_signer(SignatureAlgorithm.ECDSA_P256)


@pytest.fixture()
def pq_signer():
    """Composite ML-DSA-65 + Ed25519 signer, or skip when the backend is absent."""
    try:
        return _make_signer(SignatureAlgorithm.COMPOSITE_ML_DSA_65_ED25519)
    except (NotImplementedError, RuntimeError) as exc:  # pragma: no cover - env dependent
        pytest.skip(f"post-quantum composite backend unavailable: {exc}")


@pytest.fixture()
def attestor(ecdsa_signer):
    """An enabled attestor backed by the always-available ECDSA signer, so the
    functional tests run on every machine."""
    return build_presence_attestor(enabled=True, signer=ecdsa_signer)


@pytest.fixture()
def evidence_ref():
    return EvidenceRef(
        record_id="decision-1",
        record_hash="a" * 64,
        store="decision_store",
        field="verdict",
    )


@pytest.fixture()
def claim():
    return PresenceClaim(
        claim_id="forbid_count",
        text_span="There are 3 forbids on record.",
        kind=ClaimKind.AGGREGATE,
    )


@pytest.fixture()
def sealed_verdict(evidence_ref):
    return PresenceVerdict(
        claim_id="forbid_count",
        tier=PresenceTier.SEALED,
        evidence=(evidence_ref,),
        recomputed_value=3,
        reason="recomputed-from-rows",
    )


@pytest.fixture()
def abstain_verdict():
    return PresenceVerdict(
        claim_id="forbid_count",
        tier=PresenceTier.ABSTAIN,
        evidence=(),
        reason="no-matching-query",
    )


@pytest.fixture()
def envelope(claim, sealed_verdict):
    """A second supported claim is included so the envelope path attests >1."""
    ref2 = EvidenceRef(
        record_id="agent-7", record_hash="b" * 64, store="agent_registry", field="lifecycle_status"
    )
    claim2 = PresenceClaim(
        claim_id="agent_status:550e8400-e29b-41d4-a716-446655440000",
        text_span="Agent 7 is active.",
        kind=ClaimKind.ENTITY,
    )
    verdict2 = PresenceVerdict(
        claim_id="agent_status:550e8400-e29b-41d4-a716-446655440000",
        tier=PresenceTier.SEALED,
        evidence=(ref2,),
        recomputed_value="active",
        reason="recomputed-from-rows",
    )
    return AnswerEnvelope(
        spoken_text="There are 3 forbids on record. Agent 7 is active.",
        claims=(claim, claim2),
        verdicts=(sealed_verdict, verdict2),
    ).with_bound_prosody()
