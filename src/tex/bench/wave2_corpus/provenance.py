"""
Wave 2 / M0b — sealed corpus provenance: the anti-honor-system gate.

[Architecture: Layer 5 (Evidence) — proof-of-superiority tooling]

The problem this file exists to close
-------------------------------------
``certify_action_class(corpus_kind=...)`` and ``certify_verdict``'s
``neighborhood_kind`` / ``qif_corpus_kind`` gates are pure string checks
(action_class.py:590, verdict_certificate.py:519/:563): a harness that
synthesizes data and stamps it ``"field"`` mints ``certified=True`` from a
lie — the nanozk failure mode replayed in statistics. M0b's answer is
**earned provenance**: every corpus artifact travels with a sealed provenance
record (collector identity, collection method, time window, source
description, content digest), and loaders emit the ``"field"`` label ONLY
when that record verifies — integrity from the hash construction, authorship
from a PINNED public key — and its digest binds it to the exact corpus bytes.

What the seal proves — and what it cannot
-----------------------------------------
The seal proves AUTHORSHIP + INTEGRITY of the provenance *claim*, never the
claim's TRUTH (the same line ``provenance/decision_seal.py`` draws for
verdicts). A key-holder can still attest falsely; what changes is that the
false attestation is now a sealed, attributable, non-repudiable record signed
by a named identity — not an anonymous keyword argument. The structural
property the harness itself delivers is narrower and testable:

  **No builder code path can construct field provenance.** Synthetic builders
  produce ``CorpusProvenance`` only through :func:`synthetic_provenance`,
  which hard-codes ``corpus_kind=KIND_SYNTHETIC`` and the reserved generator
  method string; there is no parameter to override either. The ONLY way to
  produce a field-collection record is :func:`attest_field_provenance` — a
  separate, deliberate entry point that demands a collector identity, a
  collection method (which must NOT be the reserved synthetic-generator
  string), a real time window, and a source description. Fabricating a field
  corpus therefore requires an explicit human attestation act plus the
  signing key, and leaves a sealed record of exactly who attested what.

Mechanism (reuses the production primitives, invents no crypto)
---------------------------------------------------------------
A provenance record is sealed with the same construction
``adversarial/seal.py`` uses for red-team campaigns: sign the payload with
the production ``EvidenceChainSigner`` (ECDSA-P256 today; composite ML-DSA-65
when that backend exists — RUNTIME-DEPENDENT), embed the signature block,
hash with the centralized chain math (``tex.evidence.chain``), and write a
one-record bundle that ``tex.bench.evidence_bundle.verify_bundle`` checks
offline. The canonical verifier is the oracle: a byte-flip breaks integrity,
a re-signed forgery passes integrity but fails the Tex key pin.

Maturity: the sealing crypto is production (live signer + canonical
verifier); the provenance *discipline* is research-solid — newly wired, not
yet exercised by a real field collection (none exists yet; see field_trial).
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable
from uuid import NAMESPACE_URL, uuid5

from pydantic import BaseModel, ConfigDict, Field, model_validator

from tex.bench.evidence_bundle import (
    BundleVerification,
    read_bundle,
    verify_bundle,
    write_bundle,
)
from tex.domain.evidence import EvidenceRecord
from tex.evidence.chain import _build_record_hash, _sha256_hex, _stable_json
from tex.evidence.seal import PQ_SIGNATURE_FIELD, EvidenceChainSigner

PROVENANCE_SCHEMA = "tex.bench.wave2_corpus/provenance.v1"
PROVENANCE_RECORD_TYPE = "corpus_provenance"
PROVENANCE_POLICY_VERSION = "wave2-corpus-m0b-v1"

# The two provenance kinds. Deliberately NOT the bare consumer-gate strings
# ("synthetic"/"field") so a provenance record can never be string-confused
# with the gate argument it earns — the loader performs the mapping.
KIND_SYNTHETIC = "synthetic-generation"
KIND_FIELD = "field-collection"

# Reserved method string for harness-built corpora. attest_field_provenance
# REJECTS this value — a field record can never carry the generator's name.
SYNTHETIC_METHOD = "tex.bench.wave2_corpus.synthetic_builder"

# The consumers M0b builds for (ROADMAP.md:241-244).
CONSUMERS = ("action_class", "neighborhood", "qif_redteam", "nli")

# Stable namespace so the same corpus_id maps to the same logical record ids.
_NS = uuid5(NAMESPACE_URL, "tex.bench.wave2_corpus.provenance")

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
# Date or datetime, ISO-8601-shaped. Window bounds are compared as strings,
# which is order-correct for same-format ISO timestamps.
_ISO_RE = re.compile(r"^\d{4}-\d{2}-\d{2}([T ].+)?$")


class CorpusProvenance(BaseModel):
    """The provenance claim sealed alongside one corpus artifact.

    ``corpus_sha256`` binds the claim to the exact bytes of the corpus file —
    a provenance record for different bytes is a digest mismatch, not a label.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_version: str = Field(default=PROVENANCE_SCHEMA)
    corpus_id: str = Field(min_length=1, max_length=200)
    corpus_kind: str = Field(description=f"'{KIND_SYNTHETIC}' | '{KIND_FIELD}'.")
    consumer: str = Field(description="Which contract the corpus feeds: " + " | ".join(CONSUMERS))
    corpus_sha256: str = Field(description="SHA-256 hex of the corpus file bytes.")
    n_points: int = Field(ge=1, description="Number of data points in the corpus.")
    collector: str = Field(
        min_length=1,
        description="Who produced the corpus: a generator name (synthetic) or a named collector identity (field).",
    )
    collection_method: str = Field(
        min_length=1,
        description="How the data was produced/collected. Synthetic records carry the reserved generator string.",
    )
    source_description: str = Field(
        min_length=1,
        description="What distribution the corpus samples — for field corpora this seeds the certificate's family string.",
    )
    window_start: str = Field(min_length=1, description="ISO-8601 start of the collection/build window.")
    window_end: str = Field(min_length=1, description="ISO-8601 end of the collection/build window.")
    generator_seed: int | None = Field(
        default=None,
        description="PRNG seed for synthetic corpora (required there); None for field collections.",
    )

    @model_validator(mode="after")
    def _validate(self) -> "CorpusProvenance":
        if self.corpus_kind not in (KIND_SYNTHETIC, KIND_FIELD):
            raise ValueError(
                f"corpus_kind must be '{KIND_SYNTHETIC}' or '{KIND_FIELD}', got {self.corpus_kind!r}"
            )
        if self.consumer not in CONSUMERS:
            raise ValueError(f"consumer must be one of {CONSUMERS}, got {self.consumer!r}")
        if not _SHA256_RE.match(self.corpus_sha256):
            raise ValueError("corpus_sha256 must be 64 lowercase hex characters")
        for name, value in (("window_start", self.window_start), ("window_end", self.window_end)):
            if not _ISO_RE.match(value):
                raise ValueError(f"{name} must be ISO-8601-shaped, got {value!r}")
        if self.window_end < self.window_start:
            raise ValueError("window_end must not precede window_start")
        if self.corpus_kind == KIND_SYNTHETIC:
            if self.generator_seed is None:
                raise ValueError("synthetic provenance requires generator_seed (reproducibility)")
            if self.collection_method != SYNTHETIC_METHOD:
                raise ValueError(
                    f"synthetic provenance must carry the reserved method {SYNTHETIC_METHOD!r}"
                )
        else:  # KIND_FIELD
            if self.generator_seed is not None:
                raise ValueError("field provenance must not carry a generator_seed")
            if self.collection_method == SYNTHETIC_METHOD:
                raise ValueError(
                    "field provenance must not carry the reserved synthetic-generator method "
                    "string — a field collection has a real-world method"
                )
        return self


def synthetic_provenance(
    *,
    corpus_id: str,
    consumer: str,
    corpus_sha256: str,
    n_points: int,
    generator_seed: int,
    window_start: str = "2026-06-11",
    window_end: str = "2026-06-11",
) -> CorpusProvenance:
    """Provenance for a harness-built corpus. ``corpus_kind`` is HARD-CODED.

    There is deliberately no ``kind`` parameter: this is the only provenance
    constructor builders call, and it can only ever say "synthetic".
    """
    return CorpusProvenance(
        corpus_id=corpus_id,
        corpus_kind=KIND_SYNTHETIC,
        consumer=consumer,
        corpus_sha256=corpus_sha256,
        n_points=n_points,
        collector="tex.bench.wave2_corpus",
        collection_method=SYNTHETIC_METHOD,
        source_description=(
            f"synthetic corpus built by the wave2_corpus harness (seed={generator_seed}); "
            "the sampling distribution is one we wrote, not one we measured"
        ),
        window_start=window_start,
        window_end=window_end,
        generator_seed=generator_seed,
    )


def attest_field_provenance(
    *,
    corpus_id: str,
    consumer: str,
    corpus_sha256: str,
    n_points: int,
    collector: str,
    collection_method: str,
    source_description: str,
    window_start: str,
    window_end: str,
) -> CorpusProvenance:
    """The ONLY constructor of field-collection provenance — a deliberate act.

    Every argument is required and validated; the method must name a
    real-world collection process (the reserved synthetic-generator string is
    rejected). Calling this is an attestation: the named ``collector`` takes
    responsibility for the claim that these bytes were collected, not
    generated. The seal then makes that attestation attributable and
    tamper-evident — it does NOT make it true, and nothing can. No builder in
    this package calls this function (tested).
    """
    return CorpusProvenance(
        corpus_id=corpus_id,
        corpus_kind=KIND_FIELD,
        consumer=consumer,
        corpus_sha256=corpus_sha256,
        n_points=n_points,
        collector=collector,
        collection_method=collection_method,
        source_description=source_description,
        window_start=window_start,
        window_end=window_end,
        generator_seed=None,
    )


# ── sealing (the adversarial/seal.py construction, verbatim discipline) ─────


def _seal_provenance_record(
    provenance: CorpusProvenance, *, signer: EvidenceChainSigner
) -> EvidenceRecord:
    """Build the one chained, signed EvidenceRecord for a provenance claim.

    Mirrors ``adversarial.seal._seal_one``: sign the payload, embed the block,
    hash the signed payload with the centralized chain math, chain from
    genesis (a provenance bundle is a self-contained one-record chain). The
    canonical verifier (``verify_bundle``) is the oracle in tests.
    """
    payload = {
        "schema": PROVENANCE_SCHEMA,
        "record_type": PROVENANCE_RECORD_TYPE,
        **provenance.model_dump(),
    }
    block = signer.sign_payload(payload)
    signed = dict(payload)
    signed[PQ_SIGNATURE_FIELD] = block
    payload_json = _stable_json(signed)
    payload_sha256 = _sha256_hex(payload_json)
    record_hash = _build_record_hash(payload_sha256=payload_sha256, previous_hash=None)
    return EvidenceRecord(
        decision_id=uuid5(_NS, f"corpus:{provenance.corpus_id}"),
        request_id=uuid5(_NS, f"req:{provenance.corpus_id}"),
        record_type=PROVENANCE_RECORD_TYPE,
        payload_json=payload_json,
        payload_sha256=payload_sha256,
        previous_hash=None,
        record_hash=record_hash,
        policy_version=PROVENANCE_POLICY_VERSION,
    )


def seal_provenance(
    provenance: CorpusProvenance,
    *,
    signer: EvidenceChainSigner,
    bundle_path: str | Path,
) -> Path:
    """Seal one provenance claim into a one-record offline bundle file."""
    record = _seal_provenance_record(provenance, signer=signer)
    return write_bundle([record], bundle_path)


# ── verification ─────────────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class ProvenanceVerification:
    """The offline verdict on one corpus's provenance.

    ``provenance`` is the parsed claim (None when the bundle is unreadable or
    not a provenance record). Read the booleans precisely — they separate the
    properties exactly as ``BundleVerification`` does:

    - ``integrity_ok``     — the bundle's chain + self-signatures hold.
    - ``authorship_ok``    — every record signed by the PINNED key
                             (None when no pin was supplied: UNVERIFIED).
    - ``digest_matches``   — the claim binds to the exact corpus bytes given.
    - ``field_earned``     — the ONE flag loaders read to emit "field":
                             integrity AND pinned authorship AND digest match
                             AND kind == field-collection. Everything else —
                             including a perfectly valid synthetic record —
                             is False.
    """

    bundle: BundleVerification
    provenance: CorpusProvenance | None
    digest_matches: bool
    issues: tuple[str, ...]

    @property
    def integrity_ok(self) -> bool:
        return self.bundle.integrity_ok

    @property
    def authorship_ok(self) -> bool | None:
        return self.bundle.authorship_ok

    @property
    def field_earned(self) -> bool:
        return (
            self.provenance is not None
            and self.provenance.corpus_kind == KIND_FIELD
            and self.bundle.valid  # integrity + PINNED authorship
            and self.digest_matches
        )


def verify_sealed_provenance(
    bundle: str | Path | Iterable[EvidenceRecord],
    *,
    corpus_sha256: str,
    pinned_public_key_b64: str | None = None,
) -> ProvenanceVerification:
    """Verify a provenance bundle offline against the corpus digest it claims.

    Never raises on tampered input — every failure mode is a named issue, and
    ``field_earned`` stays False. Verification trusts nothing it is handed:
    the bundle verifier recomputes hashes and signatures; the digest binding
    is recomputed by the caller from the corpus bytes (see loaders).
    """
    issues: list[str] = []
    if isinstance(bundle, (str, Path)):
        try:
            records = read_bundle(bundle)
        except Exception as exc:  # noqa: BLE001 — unreadable bundle is a verdict, not a crash
            return ProvenanceVerification(
                bundle=verify_bundle((), pinned_public_key_b64=pinned_public_key_b64),
                provenance=None,
                digest_matches=False,
                issues=(f"bundle_unreadable:{exc.__class__.__name__}",),
            )
    else:
        records = tuple(bundle)

    verification = verify_bundle(records, pinned_public_key_b64=pinned_public_key_b64)

    provenance: CorpusProvenance | None = None
    if len(records) != 1:
        issues.append(f"expected_one_provenance_record_got_{len(records)}")
    if records:
        record = records[0]
        if record.record_type != PROVENANCE_RECORD_TYPE:
            issues.append(f"unexpected_record_type:{record.record_type}")
        else:
            try:
                payload = json.loads(record.payload_json)
                payload.pop(PQ_SIGNATURE_FIELD, None)
                payload.pop("schema", None)
                payload.pop("record_type", None)
                provenance = CorpusProvenance.model_validate(payload)
            except Exception as exc:  # noqa: BLE001 — malformed claim is a verdict, not a crash
                issues.append(f"provenance_payload_invalid:{exc.__class__.__name__}")

    if not verification.integrity_ok:
        issues.append("bundle_integrity_failed")
    if pinned_public_key_b64 is not None and verification.authorship_ok is not True:
        issues.append("authorship_pin_failed")

    digest_matches = provenance is not None and provenance.corpus_sha256 == corpus_sha256
    if provenance is not None and not digest_matches:
        issues.append("corpus_digest_mismatch")

    return ProvenanceVerification(
        bundle=verification,
        provenance=provenance,
        digest_matches=digest_matches,
        issues=tuple(issues),
    )


__all__ = [
    "CONSUMERS",
    "KIND_FIELD",
    "KIND_SYNTHETIC",
    "PROVENANCE_POLICY_VERSION",
    "PROVENANCE_RECORD_TYPE",
    "PROVENANCE_SCHEMA",
    "SYNTHETIC_METHOD",
    "CorpusProvenance",
    "ProvenanceVerification",
    "attest_field_provenance",
    "seal_provenance",
    "synthetic_provenance",
    "verify_sealed_provenance",
]
