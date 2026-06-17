"""
tex.provenance — identity by behaviour, sealed as proof.

The component that lets Tex stop trusting what an agent claims about
itself and start proving who it is by what it does, then seal that
identity into an externally verifiable transparency log. Fed by the
enforcement gate's decision stream (the agent action ledger), it is the
one discovery primitive that survives credential rotation, rename, and
the total absence of a self-declared identity.

Public surface:

    BehavioralSignature          content-free behavioural fingerprint
    behavioral_confidence        graded same-actor confidence in [0, 1]
    BehavioralProvenanceLedger   hash-chained + signed transparency log
    BehavioralProvenanceEngine   observe → resolve → seal
    build_default_provenance_engine()
"""

from __future__ import annotations

from tex.provenance.distance import behavioral_confidence
from tex.provenance.engine import (
    DRIFT_THRESHOLD,
    MERGE_REVIEW_LOWER,
    REIDENTIFY_THRESHOLD,
    BehavioralProvenanceEngine,
)
from tex.provenance.ledger import BehavioralProvenanceLedger, SealedFactLedger
from tex.provenance.models import (
    BehavioralBirthCertificate,
    ProvenanceEventKind,
    ProvenanceMatch,
    ProvenanceRecord,
    ProvenanceResolution,
    SealedFact,
    SealedFactKind,
    SealedFactRecord,
    SealEnvelope,
    SealPublicKey,
    SealSignature,
)
from tex.provenance.seal_envelope import (
    SEAL_VERSION_AGILE,
    CryptoAgileSealer,
    EnvelopeVerification,
    is_post_quantum_algorithm,
    verify_envelope,
)
from tex.provenance.signature import (
    WARM_OBSERVATION_THRESHOLD,
    BehavioralSignature,
)

__all__ = [
    "BehavioralSignature",
    "behavioral_confidence",
    "BehavioralProvenanceLedger",
    "BehavioralProvenanceEngine",
    "BehavioralBirthCertificate",
    "ProvenanceEventKind",
    "ProvenanceMatch",
    "ProvenanceRecord",
    "ProvenanceResolution",
    "SealedFact",
    "SealedFactKind",
    "SealedFactRecord",
    "SealedFactLedger",
    "SealEnvelope",
    "SealSignature",
    "SealPublicKey",
    "CryptoAgileSealer",
    "EnvelopeVerification",
    "verify_envelope",
    "is_post_quantum_algorithm",
    "SEAL_VERSION_AGILE",
    "WARM_OBSERVATION_THRESHOLD",
    "REIDENTIFY_THRESHOLD",
    "MERGE_REVIEW_LOWER",
    "DRIFT_THRESHOLD",
    "build_default_provenance_engine",
]


def build_default_provenance_engine() -> BehavioralProvenanceEngine:
    """
    Construct a provenance engine with a fresh signed ledger. The signing
    key is generated at construction; production deployments inject a
    keystore/HSM-backed key by building the ledger explicitly and passing
    ``signing_key=...``.
    """
    ledger = BehavioralProvenanceLedger()
    return BehavioralProvenanceEngine(ledger=ledger)
