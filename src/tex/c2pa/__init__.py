"""
C2PA Content Credentials Layer
==============================

Implements the Coalition for Content Provenance and Authenticity (C2PA)
specification for outbound AI-generated content. Every email, post, document,
or image produced by an AI-SDR running through Tex carries a tamper-evident,
cryptographically-signed manifest declaring origin, AI-generation status,
training-data class, and ingredient chain.

References
----------
- C2PA Specification 2.2 (2025-05-01) — current as of May 2026
- C2PA Conformance Program (launched mid-2025; Trust List frozen ITL
  superseded by official C2PA Trust List on 2026-01-01)
- CAWG 1.2 Extension (creator attribution)
- EU AI Act Article 50 (transparency for AI-generated content, enforces 2026-08-02)
- California SB 942 / AB 853 (operative 2026-08-02)
- New York AI Advertising Disclosure (June 2026)
- CISA Advisory: "Strengthening Multimedia Integrity in the Generative AI Era" (Jan 2025)

Threat model
------------
Closes the verification gap for AI-SDR outbound content. Without C2PA,
recipients cannot prove content came from a sanctioned AI system. With
C2PA + ML-DSA signing, Tex provides the evidence trail FTC investigators
and EU notified bodies require under Art. 50.

Priority
--------
P0 — ship in days 1-14. Together with `pqcrypto/`, this is the regulatory
forced-buyer wedge.
"""

from tex.c2pa.manifest import (
    ASSERTION_LABEL_ACTIONS_V2,
    ASSERTION_LABEL_CAWG_CREATIVE_WORK,
    ASSERTION_LABEL_TEX_VERDICT,
    DIGITAL_SOURCE_TYPE_TRAINED_ALGORITHMIC,
    TEX_VERDICT_SCHEMA_V1,
    C2paAssertion,
    C2paClaim,
    C2paIngredient,
    C2paManifest,
    build_ai_generation_assertion,
    build_cawg_creative_work_assertion,
    build_email_manifest,
    build_tex_verdict_assertion,
)
from tex.c2pa.signer import (
    clear_signing_keys,
    register_signing_key,
    set_keystore,
    sign_manifest,
)
from tex.c2pa.verifier import C2paVerificationResult, verify_manifest

__all__ = [
    # data model
    "C2paManifest",
    "C2paAssertion",
    "C2paClaim",
    "C2paIngredient",
    # builders
    "build_ai_generation_assertion",
    "build_cawg_creative_work_assertion",
    "build_email_manifest",
    "build_tex_verdict_assertion",
    # constants
    "ASSERTION_LABEL_ACTIONS_V2",
    "ASSERTION_LABEL_CAWG_CREATIVE_WORK",
    "ASSERTION_LABEL_TEX_VERDICT",
    "DIGITAL_SOURCE_TYPE_TRAINED_ALGORITHMIC",
    "TEX_VERDICT_SCHEMA_V1",
    # signer / keystore
    "sign_manifest",
    "register_signing_key",
    "clear_signing_keys",
    "set_keystore",
    # verifier
    "verify_manifest",
    "C2paVerificationResult",
]
