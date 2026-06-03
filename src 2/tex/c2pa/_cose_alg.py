"""
COSE algorithm identifier mapping for the C2PA signer/verifier.

Maps `tex.pqcrypto.algorithm_agility.SignatureAlgorithm` enum values to
the COSE `alg` integer label per the IANA COSE Algorithms registry and
C2PA 2.2 §13.2.

C2PA 2.2 §13.2 allowed list (with COSE alg labels):

    ES256  → -7    (ECDSA P-256 + SHA-256)
    ES384  → -35   (ECDSA P-384 + SHA-384)
    ES512  → -36   (ECDSA P-521 + SHA-512)
    PS256  → -37   (RSASSA-PSS + SHA-256)
    PS384  → -38   (RSASSA-PSS + SHA-384)
    PS512  → -39   (RSASSA-PSS + SHA-512)
    EdDSA  → -8    (Ed25519 only per §13.2)

ML-DSA / hybrid notes
---------------------
ML-DSA does not have a final IANA COSE alg assignment as of the C2PA 2.2
spec we're targeting; draft-ietf-cose-dilithium proposes -48..-50 for
ML-DSA-44/65/87. C2PA 2.2's allowed list does NOT include ML-DSA, so
signing a C2PA manifest under ML-DSA today would be rejected by the spec
algorithm check (§15.7 algorithm.unsupported). We therefore:

  - reject ML-DSA / SLH-DSA / hybrid for C2PA signing with a clear error
    pointing at §13.2;
  - leave the Tex-internal evidence chain (`tex.pqcrypto.evidence_chain
    _signer`) free to use ML-DSA — that's a Tex-private chain, not a
    C2PA manifest signature.

Tex's algorithm-agility provider abstraction is preserved end-to-end:
this module is the only place that bridges the Tex enum to the COSE
wire-level integer, and it's pluggable.
"""

from __future__ import annotations

from tex.pqcrypto.algorithm_agility import SignatureAlgorithm


# COSE alg labels per IANA COSE Algorithms registry, restricted to the
# C2PA 2.2 §13.2 allowed list.
COSE_ALG_ES256: int = -7
COSE_ALG_ES384: int = -35
COSE_ALG_ES512: int = -36
COSE_ALG_PS256: int = -37
COSE_ALG_PS384: int = -38
COSE_ALG_PS512: int = -39
COSE_ALG_EDDSA: int = -8


# Mapping from the Tex enum to (cose_alg_label, human_label).
# Only the algorithms allowed by C2PA 2.2 §13.2 are registered here.
_TEX_TO_COSE: dict[SignatureAlgorithm, tuple[int, str]] = {
    SignatureAlgorithm.ECDSA_P256: (COSE_ALG_ES256, "ES256"),
    SignatureAlgorithm.ED25519: (COSE_ALG_EDDSA, "EdDSA"),
}


def cose_alg_for(algorithm: SignatureAlgorithm) -> int:
    """Return the COSE `alg` integer label for ``algorithm``.

    Raises
    ------
    NotImplementedError
        If ``algorithm`` is not on the C2PA 2.2 §13.2 allowed list. The
        Tex enum is a superset of what C2PA permits — ML-DSA, SLH-DSA,
        and hybrid modes are rejected here so we never produce an
        out-of-spec C2PA manifest.
    """
    pair = _TEX_TO_COSE.get(algorithm)
    if pair is None:
        raise NotImplementedError(
            f"algorithm {algorithm.value!r} is not on the C2PA 2.2 §13.2 "
            f"allowed signature algorithm list. Allowed: ES256, ES384, "
            f"ES512, PS256, PS384, PS512, EdDSA. ML-DSA / SLH-DSA / hybrid "
            f"signatures are usable on Tex's internal evidence chain but "
            f"cannot be embedded in a C2PA manifest until the spec adds "
            f"PQ algorithms."
        )
    return pair[0]


def cose_alg_label(algorithm: SignatureAlgorithm) -> str:
    """Return the human-readable COSE label (e.g. ``"ES256"``)."""
    pair = _TEX_TO_COSE.get(algorithm)
    if pair is None:
        # Fall through to cose_alg_for for the consistent error message.
        cose_alg_for(algorithm)
    assert pair is not None  # for type checker
    return pair[1]


def is_supported(algorithm: SignatureAlgorithm) -> bool:
    """True iff ``algorithm`` can be embedded in a C2PA manifest signature."""
    return algorithm in _TEX_TO_COSE
