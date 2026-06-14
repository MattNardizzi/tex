"""
Wave 2 / M0b — corpus artifact I/O and the kind gate.

[Architecture: Layer 5 (Evidence) — proof-of-superiority tooling]

THE GATE (the file's whole reason to exist): ``load_corpus`` is the only
place a corpus acquires its ``kind``, and the ``"field"`` label is emitted
ONLY when a sealed field-collection provenance record is present, verifies
(integrity + PINNED authorship), and binds — by SHA-256 — to the exact bytes
being loaded. Everything else is ``"synthetic"`` or an exception:

  * no provenance bundle                      → ``synthetic`` (claims nothing)
  * valid synthetic-generation provenance     → ``synthetic``
  * field claim, no pinned key supplied       → raise (authorship UNVERIFIED;
    the bundle docstring's re-sign attack is exactly why integrity alone
    cannot earn the label)
  * any supplied bundle that fails to verify,
    mismatches the corpus digest, or
    contradicts the corpus manifest           → raise ``CorpusProvenanceError``
    (a tampered artifact is attack evidence; it must not silently feed
    calibration as anything)
  * field claim, verifies against the pin,
    digest + manifest bind                    → ``field``

Downstream, the adapter functions feed the consumers' ``corpus_kind`` /
``qif_corpus_kind`` arguments FROM the loaded kind — the caller never types
the honor-system string again. The consumer contracts themselves are
unchanged (M0b slots into them).

Serialization is canonical (sorted-key compact JSON, one point per line,
manifest first) so a deterministic builder yields byte-identical files and a
stable digest. Round-trips are exact and tested.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Sequence

from tex.camel.capability import CapabilityLevel, ConfidentialityLevel
from tex.contracts.action_class import (
    ActionClassCase,
    ActionClassCertificate,
    certify_action_class,
)
from tex.engine.verdict_certificate import (
    VERDICT_ALPHABET,
    VerdictCertificate,
    certify_verdict,
)
from tex.bench.wave2_corpus.builders import (
    GATE_OUTCOMES,
    NLI_LABELS,
    NLI_SOURCES,
    NLIPair,
    QIFRedTeamPoint,
    as_qif_samples,
)
from tex.bench.wave2_corpus.provenance import (
    CONSUMERS,
    KIND_FIELD,
    CorpusProvenance,
    ProvenanceVerification,
    verify_sealed_provenance,
)

CORPUS_SCHEMA = "tex.bench.wave2_corpus/corpus.v1"

# The vocabulary the consumer gates validate — the loader emits ONLY these.
LOADED_KIND_SYNTHETIC = "synthetic"
LOADED_KIND_FIELD = "field"


class CorpusProvenanceError(ValueError):
    """A supplied provenance bundle failed verification or binding.

    Raised — never downgraded — because a tampered or contradicted artifact
    is evidence of an attack and must not silently feed calibration.
    """


# ── point codecs (closed-world: decoding validates every vocabulary) ─────────


def _encode_point(consumer: str, point: Any) -> dict[str, Any]:
    if consumer == "action_class":
        return {
            "declared_steps": [list(step) for step in point.declared_steps],
            "ground_truth_must_forbid": point.ground_truth_must_forbid,
        }
    if consumer == "neighborhood":
        return {"text": point}
    if consumer == "qif_redteam":
        return {
            "prompt": point.prompt,
            "integrity": point.integrity,
            "confidentiality": point.confidentiality,
            "secret_label": point.secret_label,
            "verdict": point.verdict,
        }
    if consumer == "nli":
        return {
            "premise": point.premise,
            "hypothesis": point.hypothesis,
            "label": point.label,
            "gate_outcome": point.gate_outcome,
            "source": point.source,
        }
    raise ValueError(f"unknown consumer {consumer!r}")


def _decode_point(consumer: str, row: dict[str, Any]) -> Any:
    if consumer == "action_class":
        steps = tuple(
            (str(step[0]), str(step[1])) for step in row["declared_steps"]
        )
        return ActionClassCase(
            declared_steps=steps,
            ground_truth_must_forbid=bool(row["ground_truth_must_forbid"]),
        )
    if consumer == "neighborhood":
        text = row["text"]
        if not isinstance(text, str) or not text:
            raise ValueError("neighborhood point must be a non-empty text")
        return text
    if consumer == "qif_redteam":
        if row["verdict"] not in VERDICT_ALPHABET:
            raise ValueError(
                f"verdict {row['verdict']!r} outside the 3-outcome channel {VERDICT_ALPHABET}"
            )
        if row["confidentiality"] not in ConfidentialityLevel.__members__:
            raise ValueError(f"unknown confidentiality tier {row['confidentiality']!r}")
        if row["integrity"] not in CapabilityLevel.__members__:
            raise ValueError(f"unknown integrity level {row['integrity']!r}")
        if row["secret_label"] != row["confidentiality"]:
            raise ValueError("secret_label must equal the confidentiality tier (FIDES tag)")
        return QIFRedTeamPoint(
            prompt=str(row["prompt"]),
            integrity=row["integrity"],
            confidentiality=row["confidentiality"],
            secret_label=row["secret_label"],
            verdict=row["verdict"],
        )
    if consumer == "nli":
        if row["label"] not in NLI_LABELS:
            raise ValueError(
                f"NLI label {row['label']!r} outside the closed world {NLI_LABELS}"
            )
        if row["gate_outcome"] not in GATE_OUTCOMES:
            raise ValueError(
                f"gate_outcome {row['gate_outcome']!r} outside the gate vocabulary {GATE_OUTCOMES}"
            )
        if row["source"] not in NLI_SOURCES:
            raise ValueError(f"unknown NLI source {row['source']!r}")
        return NLIPair(
            premise=str(row["premise"]),
            hypothesis=str(row["hypothesis"]),
            label=row["label"],
            gate_outcome=row["gate_outcome"],
            source=row["source"],
        )
    raise ValueError(f"unknown consumer {consumer!r}")


# ── artifact I/O ─────────────────────────────────────────────────────────────


def _canonical_line(obj: dict[str, Any]) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def write_corpus(
    points: Sequence[Any],
    *,
    consumer: str,
    corpus_id: str,
    path: str | Path,
    n_calibration: int | None = None,
) -> str:
    """Write one corpus artifact canonically; return its SHA-256 (over bytes).

    The digest is what provenance binds to — compute it from THIS return
    value (or ``corpus_digest``), never from memory.
    """
    if consumer not in CONSUMERS:
        raise ValueError(f"consumer must be one of {CONSUMERS}, got {consumer!r}")
    if not points:
        raise ValueError("an empty corpus is not an artifact — nothing to label")
    if n_calibration is not None and not 0 < n_calibration < len(points):
        raise ValueError("n_calibration must split the corpus into two non-empty parts")
    manifest = {
        "schema": CORPUS_SCHEMA,
        "consumer": consumer,
        "corpus_id": corpus_id,
        "n_points": len(points),
        "n_calibration": n_calibration,
    }
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    lines = [_canonical_line(manifest)]
    lines += [_canonical_line(_encode_point(consumer, p)) for p in points]
    data = ("\n".join(lines) + "\n").encode("utf-8")
    out.write_bytes(data)
    return hashlib.sha256(data).hexdigest()


def corpus_digest(path: str | Path) -> str:
    """SHA-256 over the artifact's exact bytes — the provenance binding."""
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


@dataclass(frozen=True, slots=True)
class LoadedCorpus:
    """A corpus plus the kind it EARNED (never the kind someone typed)."""

    consumer: str
    corpus_id: str
    kind: str  # LOADED_KIND_SYNTHETIC | LOADED_KIND_FIELD
    points: tuple[Any, ...]
    n_calibration: int | None
    provenance: CorpusProvenance | None
    verification: ProvenanceVerification | None


def load_corpus(
    path: str | Path,
    *,
    provenance_bundle: str | Path | None = None,
    pinned_public_key_b64: str | None = None,
) -> LoadedCorpus:
    """Load one corpus artifact and resolve its kind through the gate.

    See the module docstring for the complete gate table. The short version:
    ``field`` is EARNED (sealed field provenance + pin + digest binding) or it
    is not emitted; a supplied bundle that fails anything raises.
    """
    src = Path(path)
    lines = src.read_text(encoding="utf-8").splitlines()
    if not lines:
        raise ValueError(f"empty corpus file: {src}")
    manifest = json.loads(lines[0])
    if manifest.get("schema") != CORPUS_SCHEMA:
        raise ValueError(f"not a wave2_corpus artifact (schema={manifest.get('schema')!r})")
    consumer = manifest["consumer"]
    corpus_id = manifest["corpus_id"]
    n_calibration = manifest.get("n_calibration")
    points = tuple(
        _decode_point(consumer, json.loads(line)) for line in lines[1:] if line.strip()
    )
    if len(points) != int(manifest["n_points"]):
        raise ValueError(
            f"manifest claims {manifest['n_points']} points, file carries {len(points)}"
        )

    if provenance_bundle is None:
        return LoadedCorpus(
            consumer=consumer,
            corpus_id=corpus_id,
            kind=LOADED_KIND_SYNTHETIC,
            points=points,
            n_calibration=n_calibration,
            provenance=None,
            verification=None,
        )

    digest = corpus_digest(src)
    verification = verify_sealed_provenance(
        provenance_bundle,
        corpus_sha256=digest,
        pinned_public_key_b64=pinned_public_key_b64,
    )
    provenance = verification.provenance
    if provenance is None or not verification.integrity_ok or not verification.digest_matches:
        raise CorpusProvenanceError(
            f"provenance bundle failed verification for {src.name}: "
            f"issues={list(verification.issues)}"
        )
    if pinned_public_key_b64 is not None and verification.authorship_ok is not True:
        raise CorpusProvenanceError(
            f"provenance authorship failed the key pin for {src.name}: "
            f"issues={list(verification.issues)} — a re-signed forgery looks exactly "
            "like this (integrity passes, pin fails)"
        )
    if (
        provenance.corpus_id != corpus_id
        or provenance.consumer != consumer
        or provenance.n_points != len(points)
    ):
        raise CorpusProvenanceError(
            "provenance claim contradicts the corpus manifest "
            f"(id {provenance.corpus_id!r} vs {corpus_id!r}, "
            f"consumer {provenance.consumer!r} vs {consumer!r}, "
            f"n {provenance.n_points} vs {len(points)})"
        )

    if provenance.corpus_kind == KIND_FIELD:
        if pinned_public_key_b64 is None:
            raise CorpusProvenanceError(
                "field provenance requires a pinned public key: without the pin, "
                "authorship is UNVERIFIED and a re-signed forgery would pass — "
                "integrity alone cannot earn the 'field' label"
            )
        # bundle.valid (integrity + pinned authorship) + digest + kind: earned.
        assert verification.field_earned  # by construction of the checks above
        kind = LOADED_KIND_FIELD
    else:
        kind = LOADED_KIND_SYNTHETIC

    return LoadedCorpus(
        consumer=consumer,
        corpus_id=corpus_id,
        kind=kind,
        points=points,
        n_calibration=n_calibration,
        provenance=provenance,
        verification=verification,
    )


def action_class_split(
    corpus: LoadedCorpus,
) -> tuple[tuple[ActionClassCase, ...], tuple[ActionClassCase, ...]]:
    """(calibration, holdout) from the manifest's recorded split."""
    if corpus.consumer != "action_class":
        raise ValueError(f"not an action_class corpus: {corpus.consumer!r}")
    if corpus.n_calibration is None:
        raise ValueError("corpus carries no calibration split in its manifest")
    n = corpus.n_calibration
    return corpus.points[:n], corpus.points[n:]


# ── adapters: the consumers' kind argument now FLOWS from the gate ───────────

# The anti-circularity tripwire threshold, mirroring action_class.py:699-707:
# a corpus whose holdout shows fewer genuine under-classification events than
# this yields a vacuous bound (nothing for the floor to miss), so certifying
# over it — field or synthetic — is refused rather than rubber-stamped.
MIN_HOLDOUT_MISSES = 20


def certify_action_class_corpus(
    corpus: LoadedCorpus,
    *,
    alpha: float = 0.05,
    delta: float = 0.05,
    min_holdout_misses: int = MIN_HOLDOUT_MISSES,
) -> ActionClassCertificate:
    """L4 certification with ``corpus_kind`` EARNED, not typed.

    Delegates to ``certify_action_class`` verbatim; the only added behaviour
    is (a) the kind comes from the loader's gate and (b) the >=20-miss
    holdout tripwire fires for EVERY kind — a field corpus with no genuine
    under-classification events proves nothing about the floor's miss rate,
    so it must be rejected, not certified vacuously (PROMPT/ROADMAP both name
    this trap).
    """
    calibration, holdout = action_class_split(corpus)
    holdout_misses = sum(1 for c in holdout if c.is_under_classification)
    if holdout_misses < min_holdout_misses:
        raise CorpusProvenanceError(
            f"anti-circularity tripwire: only {holdout_misses} genuine "
            f"under-classification events in the holdout (need >= {min_holdout_misses}); "
            "the bound would be vacuous"
        )
    return certify_action_class(
        calibration,
        holdout=holdout,
        alpha=alpha,
        delta=delta,
        corpus_kind=corpus.kind,
    )


def certify_action_class_from_artifact(
    corpus_path: str | Path,
    *,
    provenance_bundle: str | Path | None = None,
    pinned_public_key_b64: str | None = None,
    alpha: float = 0.05,
    delta: float = 0.05,
) -> tuple[LoadedCorpus, ActionClassCertificate]:
    """Offline re-verification entry point for the L4 certificate (from files).

    The L4 analog of ``field_trial.run_field_neighborhood_trial``: it re-runs the
    WHOLE offline check from bytes + pin alone — ``load_corpus`` re-verifies the
    sealed provenance (integrity + pinned authorship + SHA-256 digest binding) and
    re-earns the corpus kind, then ``certify_action_class_corpus`` re-derives the
    certificate. No live runtime is needed (L4 cases carry their labels), so the
    re-derivation is fully deterministic: an auditor handed the same corpus file,
    provenance bundle and pin recomputes the identical ``certified`` bit. Returns
    the loaded corpus (so the caller can read the EARNED ``kind``) alongside the
    certificate.
    """
    loaded = load_corpus(
        corpus_path,
        provenance_bundle=provenance_bundle,
        pinned_public_key_b64=pinned_public_key_b64,
    )
    cert = certify_action_class_corpus(loaded, alpha=alpha, delta=delta)
    return loaded, cert


def qif_certificate_from_corpus(
    corpus: LoadedCorpus,
    *,
    alpha: float = 0.05,
) -> VerdictCertificate:
    """L12 QIF half with ``qif_corpus_kind`` EARNED, not typed.

    The QIF half is estimate-only by contract (``qif_certified`` is pinned
    ``Literal[False]``) — even a field corpus here never mints a guarantee;
    the kind still matters because the certificate names its corpus honestly.
    """
    if corpus.consumer != "qif_redteam":
        raise ValueError(f"not a qif_redteam corpus: {corpus.consumer!r}")
    return certify_verdict(
        qif_samples=as_qif_samples(corpus.points),
        qif_corpus_kind=corpus.kind,
        alpha=alpha,
    )


__all__ = [
    "CORPUS_SCHEMA",
    "LOADED_KIND_FIELD",
    "LOADED_KIND_SYNTHETIC",
    "MIN_HOLDOUT_MISSES",
    "CorpusProvenanceError",
    "LoadedCorpus",
    "action_class_split",
    "certify_action_class_corpus",
    "certify_action_class_from_artifact",
    "corpus_digest",
    "load_corpus",
    "qif_certificate_from_corpus",
    "write_corpus",
]
