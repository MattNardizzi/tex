"""
tex.verifier — the standalone offline verdict checker.

The public surface re-exported here is the *checker* only: it has the smallest
possible trusted computing base (the Python standard library plus
``cryptography``) and imports **no** Tex decision-engine code. The producer-side
bridge that mints a portable bundle from a live ledger lives in
``tex.verifier.export`` and is imported explicitly by producers/tests — it is
deliberately NOT re-exported here, so ``import tex.verifier`` keeps the checker's
TCB tiny and auditable.

    python -m tex.verifier <bundle.json> --pin <public_key.pem>
"""

from __future__ import annotations

from tex.verifier.check import (
    PORTABLE_BUNDLE_VERSION,
    RecordReport,
    SignatureResult,
    VerificationReport,
    check_monotonicity_witness,
    load_bundle,
    verify_bundle,
)

__all__ = [
    "PORTABLE_BUNDLE_VERSION",
    "RecordReport",
    "SignatureResult",
    "VerificationReport",
    "check_monotonicity_witness",
    "load_bundle",
    "verify_bundle",
]
