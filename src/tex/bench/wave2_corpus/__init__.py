"""
Wave 2 / M0b — the calibration-corpus harness (ROADMAP.md:241-244).

Reproducible builders for the labelled corpora three leaps need (L4
action-class reversibility×blast labels; L12 robustness/QIF with FIDES
confidentiality tags, doubling as the CRC red-team corpus; L11 closed-world
NLI answer-vs-sealed-fact pairs), plus the piece that makes the labels mean
something: SEALED provenance and loaders that emit ``corpus_kind="field"``
only when a verified field-collection attestation binds to the exact corpus
bytes. Until real field data is collected, everything this package builds is
``synthetic`` and every certificate over it reads ``certified=False`` — by
design.

Layout:
  * ``provenance`` — CorpusProvenance, sealing, offline verification (the gate's
    cryptographic half; reuses the production signer + canonical bundle verifier).
  * ``builders``   — deterministic seeded synthetic builders emitting the exact
    consumer types.
  * ``loaders``    — canonical artifact I/O, the kind gate, and the adapters that
    feed consumers an EARNED kind.
  * ``field_trial`` — the separate L12 field entry point + minimum-size math.
"""

from tex.bench.wave2_corpus.builders import (
    GATE_OUTCOMES,
    NLI_LABELS,
    NLIPair,
    QIFRedTeamPoint,
    as_qif_samples,
    build_action_class_points,
    build_neighborhood_texts,
    build_nli_pairs,
    build_qif_redteam_points,
    corpus_id_for,
)
from tex.bench.wave2_corpus.field_trial import (
    FieldNeighborhoodTrialResult,
    clopper_pearson_minimum_n,
    field_family,
    minimum_field_corpus_size,
    run_field_neighborhood_trial,
)
from tex.bench.wave2_corpus.loaders import (
    CorpusProvenanceError,
    LoadedCorpus,
    action_class_split,
    certify_action_class_corpus,
    corpus_digest,
    load_corpus,
    qif_certificate_from_corpus,
    write_corpus,
)
from tex.bench.wave2_corpus.provenance import (
    KIND_FIELD,
    KIND_SYNTHETIC,
    CorpusProvenance,
    ProvenanceVerification,
    attest_field_provenance,
    seal_provenance,
    synthetic_provenance,
    verify_sealed_provenance,
)

__all__ = [
    "GATE_OUTCOMES",
    "KIND_FIELD",
    "KIND_SYNTHETIC",
    "NLI_LABELS",
    "CorpusProvenance",
    "CorpusProvenanceError",
    "FieldNeighborhoodTrialResult",
    "LoadedCorpus",
    "NLIPair",
    "ProvenanceVerification",
    "QIFRedTeamPoint",
    "action_class_split",
    "as_qif_samples",
    "attest_field_provenance",
    "build_action_class_points",
    "build_neighborhood_texts",
    "build_nli_pairs",
    "build_qif_redteam_points",
    "certify_action_class_corpus",
    "clopper_pearson_minimum_n",
    "corpus_digest",
    "corpus_id_for",
    "field_family",
    "load_corpus",
    "minimum_field_corpus_size",
    "qif_certificate_from_corpus",
    "run_field_neighborhood_trial",
    "seal_provenance",
    "synthetic_provenance",
    "verify_sealed_provenance",
    "write_corpus",
]
