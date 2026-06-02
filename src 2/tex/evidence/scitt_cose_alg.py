"""
COSE algorithm identifier mapping for SCITT Signed Statements.

This module is the SCITT counterpart to ``tex.c2pa._cose_alg``. It maps
``tex.pqcrypto.algorithm_agility.SignatureAlgorithm`` values to COSE
``alg`` integer labels for use in COSE_Sign1 envelopes carrying SCITT
claim sets.

Why a separate module
---------------------
The C2PA module deliberately restricts allowed algorithms to the
C2PA 2.2 §13.2 whitelist (ES256/ES384/ES512/PS256/PS384/PS512/EdDSA)
and **rejects ML-DSA**. That is correct for C2PA manifest signing but
wrong for SCITT, where the architecture draft is explicit:

    "Because the SCITT Architecture leverages [STD96] for Statements
    and Receipts, it benefits from the format's cryptographic
    agility."  -- draft-ietf-scitt-architecture-22 §6

Tex's evidence chain is internal and audit-grade; we want to support
the full Tex algorithm-agility surface, including ML-DSA-44/65/87 for
the post-quantum migration. This module therefore maps the entire Tex
enum.

ML-DSA COSE labels
------------------
The IANA COSE Algorithms registry has not yet assigned final integers
for ML-DSA. ``draft-ietf-cose-dilithium`` (latest revision -06,
March 2026) proposes -48/-49/-50 for ML-DSA-44/65/87 respectively.
We use those values, clearly documented as **provisional** pending
IANA assignment. The verifier side is symmetric — it accepts the same
provisional labels.

Hybrid signatures
-----------------
``HYBRID_ML_DSA_ED25519`` is a Tex-internal transition algorithm; it
has no COSE label assignment. We expose it under a Tex-private
negative label (-65000, well outside the IANA COSE alg range which
runs -260..+65535 with negatives reserved). Verifiers MUST treat
unknown alg labels as failure-to-verify per RFC 9052 §3.

References
----------
- RFC 9052 (COSE Structures), STD 96
- RFC 9360 (X.509 in COSE)
- draft-ietf-scitt-architecture-22 §6
- draft-kamimura-scitt-refusal-events-02 §5.1 (Encoding as Signed
  Statements)
- draft-ietf-cose-dilithium-06 (ML-DSA COSE labels, provisional)

Companion to ``tex.c2pa._cose_alg`` (which it deliberately does not
replace).
"""

from __future__ import annotations

from tex.pqcrypto.algorithm_agility import SignatureAlgorithm


# IANA-assigned COSE alg labels (RFC 9052 / IANA COSE Algorithms registry).
COSE_ALG_ES256: int = -7
COSE_ALG_EDDSA: int = -8


# Provisional COSE alg labels from draft-ietf-cose-dilithium-06.
# These are **subject to change** when IANA assignment finalizes.
# A schema upgrade plan is straightforward because the algorithm-agility
# layer abstracts the wire-level integer from call sites.
COSE_ALG_ML_DSA_44_PROVISIONAL: int = -48
COSE_ALG_ML_DSA_65_PROVISIONAL: int = -49
COSE_ALG_ML_DSA_87_PROVISIONAL: int = -50

# Provisional SLH-DSA label from draft-ietf-cose-sphincs-plus-04.
COSE_ALG_SLH_DSA_128S_PROVISIONAL: int = -51

# Tex-private label for the hybrid transition algorithm. Outside the
# normal IANA-assigned range so it cannot collide. Verifiers that don't
# understand Tex's hybrid mode will reject — which is the intended
# fail-closed behaviour.
COSE_ALG_HYBRID_ML_DSA_ED25519_PRIVATE: int = -65000


# Bridge from Tex's algorithm-agility enum to (cose_alg, human_label).
_TEX_TO_COSE: dict[SignatureAlgorithm, tuple[int, str]] = {
    SignatureAlgorithm.ECDSA_P256: (COSE_ALG_ES256, "ES256"),
    SignatureAlgorithm.ED25519: (COSE_ALG_EDDSA, "EdDSA"),
    SignatureAlgorithm.ML_DSA_44: (
        COSE_ALG_ML_DSA_44_PROVISIONAL,
        "ML-DSA-44 (provisional)",
    ),
    SignatureAlgorithm.ML_DSA_65: (
        COSE_ALG_ML_DSA_65_PROVISIONAL,
        "ML-DSA-65 (provisional)",
    ),
    SignatureAlgorithm.ML_DSA_87: (
        COSE_ALG_ML_DSA_87_PROVISIONAL,
        "ML-DSA-87 (provisional)",
    ),
    SignatureAlgorithm.SLH_DSA_128S: (
        COSE_ALG_SLH_DSA_128S_PROVISIONAL,
        "SLH-DSA-128s (provisional)",
    ),
    SignatureAlgorithm.HYBRID_ML_DSA_ED25519: (
        COSE_ALG_HYBRID_ML_DSA_ED25519_PRIVATE,
        "Hybrid ML-DSA-65 + Ed25519 (Tex-private)",
    ),
}


def cose_alg_for(algorithm: SignatureAlgorithm) -> int:
    """Return the COSE ``alg`` integer label for a SCITT signed statement.

    Supports the **full** Tex algorithm-agility surface — unlike the
    C2PA-conformant ``tex.c2pa._cose_alg.cose_alg_for`` which restricts
    to a narrow whitelist.

    Raises
    ------
    NotImplementedError
        If ``algorithm`` is not registered in the SCITT alg map. This
        is a programmer error — every Tex algorithm should be present.
    """
    pair = _TEX_TO_COSE.get(algorithm)
    if pair is None:
        raise NotImplementedError(
            f"algorithm {algorithm.value!r} is not registered in the SCITT "
            f"COSE alg map. Add a mapping in tex.evidence.scitt_cose_alg "
            f"and pin the COSE label."
        )
    return pair[0]


def cose_alg_label(algorithm: SignatureAlgorithm) -> str:
    """Return the human-readable COSE label for ``algorithm``."""
    pair = _TEX_TO_COSE.get(algorithm)
    if pair is None:
        # Reuse the consistent error path.
        cose_alg_for(algorithm)
    assert pair is not None  # for type checker
    return pair[1]


def is_provisional(algorithm: SignatureAlgorithm) -> bool:
    """True iff the COSE label for ``algorithm`` is provisional (not
    yet IANA-assigned). Auditors may want to flag these statements."""
    return algorithm in (
        SignatureAlgorithm.ML_DSA_44,
        SignatureAlgorithm.ML_DSA_65,
        SignatureAlgorithm.ML_DSA_87,
        SignatureAlgorithm.SLH_DSA_128S,
        SignatureAlgorithm.HYBRID_ML_DSA_ED25519,
    )


__all__ = [
    "COSE_ALG_ES256",
    "COSE_ALG_EDDSA",
    "COSE_ALG_ML_DSA_44_PROVISIONAL",
    "COSE_ALG_ML_DSA_65_PROVISIONAL",
    "COSE_ALG_ML_DSA_87_PROVISIONAL",
    "COSE_ALG_SLH_DSA_128S_PROVISIONAL",
    "COSE_ALG_HYBRID_ML_DSA_ED25519_PRIVATE",
    "cose_alg_for",
    "cose_alg_label",
    "is_provisional",
]
