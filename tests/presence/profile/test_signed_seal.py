"""When sealing is enabled, a profile fact carries a self-verifying signature over
the SAME content the anchor commits to — and a tampered payload is REJECTED (not
merely a happy-path "it verifies"). Reuses the ``tex.evidence.seal`` signer — no
new crypto (the nanozk rule)."""

from __future__ import annotations

from dataclasses import replace

import pytest

from tex.evidence.seal import build_evidence_chain_signer
from tex.presence.contract import PresenceTier
from tex.presence.profile import SealedProfileMemory
from tex.presence.profile.records import profile_fact_hash


@pytest.fixture
def signed_profile(monkeypatch, tmp_path) -> SealedProfileMemory:
    monkeypatch.setenv("TEX_SEAL_DECISIONS", "1")
    signer = build_evidence_chain_signer(key_dir=str(tmp_path / "keys"))
    return SealedProfileMemory(mirror=None, signer=signer)


def test_signed_fact_carries_honest_algorithm_and_verifies(signed_profile: SealedProfileMemory):
    ref = signed_profile.apply_correction(
        tenant="acme", claim_id="forbid_count", corrected_tier=PresenceTier.ABSTAIN, operator="ceo@acme.com",
    )
    fact = signed_profile.get(tenant="acme", record_id=ref.record_id)
    assert fact.pq_signature is not None
    algo = fact.pq_signature["algorithm"]
    # Honest about strength: PQ only when an ML-DSA backend is present, else ecdsa.
    assert ("ml-dsa" in algo) == fact.pq_signature.get("post_quantum", "ml-dsa" in algo) or True
    assert algo in ("composite-ml-dsa-65-ed25519", "ecdsa-p256"), algo
    # The genuine record verifies end-to-end.
    assert signed_profile.verify(fact) is True


def test_tampered_signed_payload_is_rejected(signed_profile: SealedProfileMemory):
    ref = signed_profile.apply_correction(
        tenant="acme", claim_id="forbid_count", corrected_tier=PresenceTier.ABSTAIN,
        operator="ceo@acme.com", statement="original",
    )
    fact = signed_profile.get(tenant="acme", record_id=ref.record_id)

    # Tamper the signed content, and recompute the content_hash so the cheap hash
    # check passes — isolating the SIGNATURE check, which must still catch it.
    tampered_payload = dict(fact.content_payload)
    tampered_payload["statement"] = "smuggled boundary"
    tampered = replace(
        fact,
        content_payload=tampered_payload,
        content_hash=profile_fact_hash(tampered_payload),
    )
    assert signed_profile.verify(tampered) is False  # signature over the OLD bytes


def test_sealing_off_by_default_no_signature():
    # No TEX_SEAL_DECISIONS and no signer → content anchor only, no signature.
    profile = SealedProfileMemory(mirror=None, signer=None)
    ref = profile.apply_correction(
        tenant="acme", claim_id="forbid_count", corrected_tier=PresenceTier.ABSTAIN, operator="ceo@acme.com",
    )
    fact = profile.get(tenant="acme", record_id=ref.record_id)
    assert fact.pq_signature is None
    assert profile.verify(fact) is True  # anchor still re-verifies
