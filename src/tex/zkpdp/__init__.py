"""zkPDP (Wave 2 / L1) — proof-carrying verdict over the arbitration relation.

Honesty boundary: this package proves the ARBITRATION RELATION only
(fuse → threshold → FORBID-floor → monotone gate), never the specialist
inference behind the committed scores. Backends: the SNARK options remain
RUNTIME-DEPENDENT (M0c), but ``schnorr-fuse-zk-v1`` (``tex.zkprov.zk_fuse``) is
a real, runnable, non-shim discrete-log proof of the FUSE kernel over PRIVATE
scores — with it L1 reaches *green* (``stand_in=False``) without the shim flag;
it is research-early/unaudited/non-succinct/pre-quantum and proves the fusion
arithmetic only (threshold/floor/pin/chain stay public). The default backend is
still the keyed-hash STAND-IN, which the verifier rejects by default
(``zkpdp_shim_not_a_real_proof``) unless ``TEX_ZKPDP_ALLOW_SHIM=1``.
See ``arbiter.py``'s module banner before citing anything here.
"""

from tex.zkpdp.arbiter import (
    ArbitrationEnvelope,
    ArbitrationStatement,
    ArbitrationUnprovable,
    ArbitrationVerification,
    LoweringStep,
    RelationResult,
    SealBinding,
    SHIM_GATE_REASON,
    base_verdict,
    build_statement_from_decision,
    canonical_fuse,
    check_seal_binding,
    evaluate_relation,
    expected_claimed_verdict,
    prove_arbitration,
    quantize,
    threshold_verdict,
    verify_arbitration,
)

__all__ = [
    "ArbitrationEnvelope",
    "ArbitrationStatement",
    "ArbitrationUnprovable",
    "ArbitrationVerification",
    "LoweringStep",
    "RelationResult",
    "SealBinding",
    "SHIM_GATE_REASON",
    "base_verdict",
    "build_statement_from_decision",
    "canonical_fuse",
    "check_seal_binding",
    "evaluate_relation",
    "expected_claimed_verdict",
    "prove_arbitration",
    "quantize",
    "threshold_verdict",
    "verify_arbitration",
]
