"""
Crypto-agile dual-signature seal envelope (post-quantum, FIPS 204 ML-DSA).

Pins the envelope contract the ledgers and the offline bundle rest on:

  * a ``record_hash`` is signed by BOTH ECDSA-P256 and ML-DSA-65, and both verify
    against their *pinned* keys (the envelope ``is_dual``);
  * the post-quantum signature is a REAL ML-DSA signature, not a stand-in — proven
    by its FIPS 204 byte size and by a wrong-key forgery failing to verify;
  * an algorithm-mismatch (a relabelled signature) is CAUGHT — it fails to
    validate under the wrong algorithm/key, never silently accepted;
  * tamper of the signed bytes is caught;
  * an unpinned PQ algorithm is reported honestly (cannot-confirm), not as a tamper;
  * with no PQ signer the sealer degrades honestly to ECDSA-only (``is_dual`` False).

These tests construct the PQ signer explicitly, so they exercise the real native
ML-DSA backend (``cryptography>=48``); they skip honestly if no backend is present.
"""

from __future__ import annotations

import base64

import pytest

from tex.events._ecdsa_provider import EcdsaP256Provider
from tex.pqcrypto.algorithm_agility import SignatureAlgorithm
from tex.pqcrypto.ml_dsa import (
    MlDsaProvider,
    active_backend_id,
    expected_signature_size,
)
from tex.provenance.models import SealEnvelope, SealSignature
from tex.provenance.seal_envelope import (
    SEAL_VERSION_AGILE,
    CryptoAgileSealer,
    is_post_quantum_algorithm,
    verify_envelope,
)

pytestmark = pytest.mark.skipif(
    active_backend_id() is None,
    reason="no ML-DSA backend (install cryptography>=48 or liboqs-python)",
)

ECDSA = SignatureAlgorithm.ECDSA_P256.value
MLDSA = SignatureAlgorithm.ML_DSA_65.value

# a fixed 64-hex record_hash stand-in (the ledger signs exactly this shape)
_RH = "a" * 64


def _dual_sealer() -> tuple[CryptoAgileSealer, dict[str, bytes]]:
    ep = EcdsaP256Provider()
    ek = ep.generate_keypair("seal-ecdsa")
    mp = MlDsaProvider(SignatureAlgorithm.ML_DSA_65)
    mk = mp.generate_keypair("seal-ml-dsa")
    sealer = CryptoAgileSealer.from_primary(ep, ek, pq_provider=mp, pq_key=mk)
    pins = {ECDSA: ek.public_key, MLDSA: mk.public_key}
    return sealer, pins


# --------------------------------------------------------------------------- #
# dual signing + verification
# --------------------------------------------------------------------------- #
def test_dual_sign_round_trips() -> None:
    sealer, pins = _dual_sealer()
    assert sealer.is_dual is True
    env = sealer.sign(_RH)
    assert env.seal_version == SEAL_VERSION_AGILE
    assert env.algorithms() == (ECDSA, MLDSA)
    assert env.is_dual is True

    res = verify_envelope(_RH, env, pinned_keys=pins)
    assert res.present is True
    assert set(res.verified_algorithms) == {ECDSA, MLDSA}
    assert res.ecdsa_verified is True
    assert res.pq_verified is True
    assert res.dual_verified is True
    assert res.mismatch is False


def test_pq_signature_is_real_fips204_ml_dsa() -> None:
    # The ML-DSA entry is a genuine FIPS 204 signature: right size, and it is
    # bound to its key (a different ML-DSA key cannot verify it).
    sealer, pins = _dual_sealer()
    env = sealer.sign(_RH)
    pq_sig = env.signature_for(MLDSA)
    assert pq_sig is not None
    raw = base64.b64decode(pq_sig.signature_b64)
    assert len(raw) == expected_signature_size(SignatureAlgorithm.ML_DSA_65)  # 3309

    # Forge the pin: a *different* ML-DSA key must reject the signature.
    other = MlDsaProvider(SignatureAlgorithm.ML_DSA_65).generate_keypair("other")
    forged_pins = {ECDSA: pins[ECDSA], MLDSA: other.public_key}
    res = verify_envelope(_RH, env, pinned_keys=forged_pins)
    assert res.ecdsa_verified is True   # ECDSA pin still correct
    assert res.pq_verified is False     # PQ key substitution rejected
    assert res.mismatch is True


def test_envelope_is_bound_to_its_record_hash() -> None:
    # A signature over one record_hash must not verify against another.
    sealer, pins = _dual_sealer()
    env = sealer.sign(_RH)
    res = verify_envelope("b" * 64, env, pinned_keys=pins)
    assert res.verified_algorithms == ()
    assert res.mismatch is True


# --------------------------------------------------------------------------- #
# algorithm-mismatch + tamper
# --------------------------------------------------------------------------- #
def test_algorithm_mismatch_is_caught() -> None:
    # Relabel: swap the algorithm tags so each signature is verified under the
    # WRONG algorithm/key. Both must fail — a tampered tag is never honoured.
    sealer, pins = _dual_sealer()
    env = sealer.sign(_RH)
    e_sig = env.signature_for(ECDSA)
    m_sig = env.signature_for(MLDSA)
    swapped = SealEnvelope(
        seal_version=env.seal_version,
        signatures=(
            SealSignature(algorithm=MLDSA, key_id=e_sig.key_id, signature_b64=e_sig.signature_b64),
            SealSignature(algorithm=ECDSA, key_id=m_sig.key_id, signature_b64=m_sig.signature_b64),
        ),
    )
    res = verify_envelope(_RH, swapped, pinned_keys=pins)
    assert res.verified_algorithms == ()
    assert res.mismatch is True
    assert res.dual_verified is False


def test_tampered_pq_signature_is_caught() -> None:
    sealer, pins = _dual_sealer()
    env = sealer.sign(_RH)
    m_sig = env.signature_for(MLDSA)
    raw = bytearray(base64.b64decode(m_sig.signature_b64))
    raw[0] ^= 0x01  # flip one bit
    bad = SealEnvelope(
        seal_version=env.seal_version,
        signatures=(
            env.signature_for(ECDSA),
            SealSignature(
                algorithm=MLDSA,
                key_id=m_sig.key_id,
                signature_b64=base64.b64encode(bytes(raw)).decode("ascii"),
            ),
        ),
    )
    res = verify_envelope(_RH, bad, pinned_keys=pins)
    assert res.ecdsa_verified is True   # ECDSA entry untouched
    assert res.pq_verified is False     # PQ bytes tampered
    assert res.mismatch is True


# --------------------------------------------------------------------------- #
# honesty: unpinned PQ, and graceful ECDSA-only
# --------------------------------------------------------------------------- #
def test_unpinned_pq_is_honest_not_a_mismatch() -> None:
    # Verifying with ONLY the ECDSA pin: the ECDSA entry verifies, the PQ entry is
    # reported as unpinned (cannot-confirm), NOT as a tamper.
    sealer, pins = _dual_sealer()
    env = sealer.sign(_RH)
    res = verify_envelope(_RH, env, pinned_keys={ECDSA: pins[ECDSA]})
    assert res.verified_algorithms == (ECDSA,)
    assert res.unpinned_algorithms == (MLDSA,)
    assert res.mismatch is False
    assert res.pq_verified is False


def test_ecdsa_only_when_pq_disabled() -> None:
    ep = EcdsaP256Provider()
    ek = ep.generate_keypair("e")
    sealer = CryptoAgileSealer.from_primary(ep, ek, enable_pq=False)
    assert sealer.is_dual is False
    assert sealer.pq_signer is None
    env = sealer.envelope_with_primary(_RH, base64.b64decode(_p_sign(ep, ek)))
    assert env.is_dual is False
    assert env.algorithms() == (ECDSA,)


def test_is_post_quantum_algorithm_classification() -> None:
    assert is_post_quantum_algorithm(ECDSA) is False
    assert is_post_quantum_algorithm(SignatureAlgorithm.ED25519.value) is False
    assert is_post_quantum_algorithm(MLDSA) is True
    assert is_post_quantum_algorithm(SignatureAlgorithm.ML_DSA_87.value) is True


def _p_sign(provider: EcdsaP256Provider, key) -> str:
    return base64.b64encode(provider.sign(_RH.encode("ascii"), key)).decode("ascii")
