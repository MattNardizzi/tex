"""
Wave 2 L11 seal half — the entailment COMMITMENT in the ECDSA voice chain.

What these tests earn (PROMPT/ROADMAP.md:286): the commitment round-trips
through the chain; a model swap fails replay BOTH ways (wrong expectation
detected; adversarial re-mint passes self-verification but fails the key
pin); a corpus byte-flip breaks the manifest binding; and the honesty pins —
``calibrated=True`` / a λ̂ number / ``model_loaded=True`` / a field-kind
binding are UNCONSTRUCTIBLE, and no string this module seals ever promises
what the missing scorer cannot deliver.
"""

from __future__ import annotations

import hashlib
import warnings
from pathlib import Path

import pytest
from pydantic import ValidationError

from tex.bench.wave2_corpus.builders import build_nli_pairs
from tex.bench.wave2_corpus.loaders import LoadedCorpus, corpus_digest, load_corpus, write_corpus
from tex.voice.attestation import VoiceAttestor, _stable_json
from tex.voice.entailment_cert import (
    COMMITMENT_SCHEMA,
    GATE_COMMITMENT_HASH_KEY,
    GATE_COMMITMENT_KEY,
    NO_VERDICT_MARKER,
    EntailmentCommitment,
    commitment_for_scorer,
    commitment_from_corpus,
    seal_entailment_commitment,
    verify_entailment_commitment,
)
from tex.voice.voice_gate import THRESHOLD_LABEL, NeuralNLIScorer

MODEL_A = "MoritzLaurer/DeBERTa-v3-base-mnli"
MODEL_B = "adversary/swapped-mnli-model"


def _pin_of(attestor: VoiceAttestor) -> str:
    """The honest chain's public key, read from a sealed record's own block."""
    return attestor.records()[0].payload["pq_signature"]["public_key_b64"]


def _write_nli_corpus(tmp_path: Path) -> tuple[Path, str]:
    pairs = build_nli_pairs(seed=7, n_per_class=3)
    path = tmp_path / "nli_corpus.jsonl"
    digest = write_corpus(pairs, consumer="nli", corpus_id="nli-cal-v1", path=path)
    return path, digest


# ── 1. round-trip ────────────────────────────────────────────────────────────


def test_commitment_round_trip_in_a_mixed_chain() -> None:
    at = VoiceAttestor()
    # A normal spoken-answer seal first — the commitment must coexist with the
    # chain's real traffic, exactly as the deferred live wiring would have it.
    at.seal(
        transcript="question 0",
        routed_dimension="evidence",
        verdict="PERMIT",
        answer="The evidence chain is intact across 4 sealed records.",
        object_=None,
        proof_ref=None,
        gate={"scorer": "exact-match", "reason": "reconstruction-exact"},
    )
    record = seal_entailment_commitment(at, EntailmentCommitment())
    assert record.payload["gate"][GATE_COMMITMENT_KEY]["model_id"] == MODEL_A

    assert at.verify_chain()["intact"] is True
    assert at.verify_signatures()["valid"] is True

    res = verify_entailment_commitment(at.records(), expected_model_id=MODEL_A)
    assert res.chain_intact is True
    assert res.chain_checked == 2
    assert res.signatures_valid is True
    assert len(res.commitments) == 1
    assert res.model_id_ok is True
    assert res.commitment_hashes_ok is True
    assert res.ok is True
    # No pin supplied → authorship is UNVERIFIED, reported as None, never True.
    assert res.authorship_ok is None


def test_commitment_rides_a_real_answer_seal() -> None:
    # The live-wiring shape: the commitment travels INSIDE a per-answer gate
    # dict (voice_ask._gate_summary's carrier), not only as a standalone act.
    at = VoiceAttestor()
    seal_entailment_commitment(
        at,
        EntailmentCommitment(),
        transcript="how many records are sealed",
        routed_dimension="evidence",
        verdict="PERMIT",
        answer="There are 4 sealed records and the chain is intact.",
        gate={"scorer": "exact-match", "reason": "reconstruction-exact"},
    )
    payload = at.records()[0].payload
    assert payload["verdict"] == "PERMIT"
    assert payload["gate"]["scorer"] == "exact-match"
    assert GATE_COMMITMENT_KEY in payload["gate"]
    res = verify_entailment_commitment(at.records(), expected_model_id=MODEL_A)
    assert res.ok is True


def test_seal_refuses_to_overwrite_a_prior_commitment_key() -> None:
    at = VoiceAttestor()
    with pytest.raises(ValueError, match="refusing to overwrite"):
        seal_entailment_commitment(
            at, EntailmentCommitment(), gate={GATE_COMMITMENT_KEY: {"forged": True}}
        )


# ── 2. model-swap-fails-replay (the ROADMAP earn), BOTH variants ─────────────


def test_model_swap_variant_a_wrong_expectation_is_detected() -> None:
    at = VoiceAttestor()
    seal_entailment_commitment(at, EntailmentCommitment(model_id=MODEL_A))
    res = verify_entailment_commitment(at.records(), expected_model_id=MODEL_B)
    assert res.model_id_ok is False
    assert res.ok is False
    assert any(issue.startswith("model_id_mismatch_at:0") for issue in res.issues)
    # The chain itself is fine — the mismatch is the IDENTITY, named separately.
    assert res.chain_intact is True and res.signatures_valid is True


def test_model_swap_variant_b_remint_passes_self_verification_fails_pin() -> None:
    honest = VoiceAttestor()
    seal_entailment_commitment(honest, EntailmentCommitment(model_id=MODEL_A))
    honest_pin = _pin_of(honest)

    # The adversary mints a FRESH chain (ephemeral key, attestation.py:32-36)
    # around the swapped model id. Internally it is perfect.
    adversary = VoiceAttestor()
    seal_entailment_commitment(adversary, EntailmentCommitment(model_id=MODEL_B))

    unpinned = verify_entailment_commitment(adversary.records(), expected_model_id=MODEL_B)
    assert unpinned.chain_intact is True
    assert unpinned.signatures_valid is True
    assert unpinned.model_id_ok is True
    assert unpinned.authorship_ok is None  # UNVERIFIED — the honest gap, said plainly

    pinned = verify_entailment_commitment(
        adversary.records(), expected_model_id=MODEL_B, pinned_public_key_b64=honest_pin
    )
    # The result must DISTINGUISH integrity-ok from authorship-failed.
    assert pinned.chain_intact is True
    assert pinned.signatures_valid is True
    assert pinned.authorship_ok is False
    assert pinned.ok is False
    assert any(issue.startswith("key_pin_mismatch_at") for issue in pinned.issues)

    # And the honest chain PASSES the same pin — the check has both edges.
    honest_res = verify_entailment_commitment(
        honest.records(), expected_model_id=MODEL_A, pinned_public_key_b64=honest_pin
    )
    assert honest_res.authorship_ok is True and honest_res.ok is True


def test_in_place_tamper_of_the_sealed_model_id_breaks_chain_and_signature() -> None:
    at = VoiceAttestor()
    seal_entailment_commitment(at, EntailmentCommitment(model_id=MODEL_A))
    rec = at.records()[0]
    rec.payload["gate"][GATE_COMMITMENT_KEY]["model_id"] = MODEL_B
    rec.payload["gate"][GATE_COMMITMENT_HASH_KEY] = EntailmentCommitment(
        model_id=MODEL_B
    ).commitment_sha256()

    res = verify_entailment_commitment(at.records(), expected_model_id=MODEL_A)
    assert res.chain_intact is False
    assert res.signatures_valid is False
    assert res.ok is False
    assert any(issue.startswith("chain_break_at:0") for issue in res.issues)


# ── 3. manifest binding ──────────────────────────────────────────────────────


def test_corpus_byte_flip_breaks_the_manifest_binding(tmp_path: Path) -> None:
    path, digest = _write_nli_corpus(tmp_path)
    loaded = load_corpus(path)
    assert loaded.kind == "synthetic"

    at = VoiceAttestor()
    commitment = commitment_from_corpus(loaded, corpus_sha256=digest)
    assert commitment.calibration_manifest_sha256 == digest
    assert commitment.calibration_corpus_kind == "synthetic"
    seal_entailment_commitment(at, commitment)

    good = verify_entailment_commitment(
        at.records(), expected_model_id=MODEL_A, expected_manifest_sha256=digest
    )
    assert good.manifest_ok is True and good.ok is True

    # Mutate ONE byte of the corpus artifact, then re-derive its digest the way
    # any auditor would (from the bytes they hold, loaders.corpus_digest).
    data = bytearray(path.read_bytes())
    data[len(data) // 2] ^= 0x01
    path.write_bytes(bytes(data))
    recomputed = corpus_digest(path)
    assert recomputed != digest

    bad = verify_entailment_commitment(
        at.records(), expected_model_id=MODEL_A, expected_manifest_sha256=recomputed
    )
    assert bad.manifest_ok is False
    assert bad.ok is False
    assert any(issue.startswith("calibration_manifest_mismatch_at") for issue in bad.issues)


def test_commitment_from_corpus_refuses_wrong_consumer_and_typed_field_kind() -> None:
    base = dict(points=(), n_calibration=None, provenance=None, verification=None)
    with pytest.raises(ValueError, match="not an NLI corpus"):
        commitment_from_corpus(
            LoadedCorpus(consumer="neighborhood", corpus_id="x", kind="synthetic", **base),
            corpus_sha256="0" * 64,
        )
    # The M0b direct-caller residual: a hand-built LoadedCorpus can SAY
    # kind="field" without earning it. Schema v1 has no slot to put it in.
    with pytest.raises(ValueError, match="binds 'synthetic'-kind corpora only"):
        commitment_from_corpus(
            LoadedCorpus(consumer="nli", corpus_id="x", kind="field", **base),
            corpus_sha256="0" * 64,
        )


def test_commitment_from_corpus_refuses_a_digest_contradicting_sealed_provenance(
    tmp_path: Path,
) -> None:
    path, digest = _write_nli_corpus(tmp_path)
    loaded = load_corpus(path)
    fake = LoadedCorpus(
        consumer=loaded.consumer,
        corpus_id=loaded.corpus_id,
        kind=loaded.kind,
        points=loaded.points,
        n_calibration=loaded.n_calibration,
        provenance=_synthetic_provenance_for(digest),
        verification=None,
    )
    with pytest.raises(ValueError, match="contradicts the corpus's sealed provenance"):
        commitment_from_corpus(fake, corpus_sha256="f" * 64)


def _synthetic_provenance_for(digest: str):
    from tex.bench.wave2_corpus.provenance import synthetic_provenance

    return synthetic_provenance(
        corpus_id="nli-cal-v1",
        consumer="nli",
        corpus_sha256=digest,
        n_points=12,
        generator_seed=7,
    )


# ── 4. honesty pins ──────────────────────────────────────────────────────────


def test_calibrated_true_and_lambda_hat_are_unconstructible() -> None:
    with pytest.raises(ValidationError):
        EntailmentCommitment(calibrated=True)
    with pytest.raises(ValidationError):
        EntailmentCommitment(lambda_hat=0.7)
    with pytest.raises(ValidationError):
        EntailmentCommitment(model_loaded=True)
    with pytest.raises(ValidationError):
        EntailmentCommitment(
            calibration_manifest_sha256="a" * 64,
            calibration_corpus_id="x",
            calibration_corpus_kind="field",
        )
    with pytest.raises(ValidationError):
        EntailmentCommitment(schema_version="tex.voice/entailment_commitment.v2")
    with pytest.raises(ValidationError):  # corpus fields travel together
        EntailmentCommitment(calibration_manifest_sha256="a" * 64)
    with pytest.raises(ValidationError):  # digest shape enforced
        EntailmentCommitment(
            calibration_manifest_sha256="ZZ" * 32,
            calibration_corpus_id="x",
            calibration_corpus_kind="synthetic",
        )


def test_model_loaded_mirrors_the_live_scorer_and_a_loaded_scorer_is_refused() -> None:
    scorer = NeuralNLIScorer()
    # If this env ever flips load() to True, the Literal[False] schema is stale
    # and THIS assertion forces the schema bump (it must not silently pass).
    assert scorer.load() is False
    assert EntailmentCommitment().model_loaded == scorer.load()
    assert commitment_for_scorer(scorer).model_id == scorer._model_id  # noqa: SLF001

    class _LoadedScorer(NeuralNLIScorer):
        def load(self) -> bool:
            return True

    with pytest.raises(ValueError, match="schema v1 commits a NOT-LOADED scorer"):
        commitment_for_scorer(_LoadedScorer())


def test_default_model_id_reads_the_seam_not_a_copied_string() -> None:
    assert EntailmentCommitment().model_id == NeuralNLIScorer()._model_id == MODEL_A  # noqa: SLF001


def test_standalone_seal_never_fabricates_a_verdict_event() -> None:
    assert NO_VERDICT_MARKER not in ("PERMIT", "ABSTAIN", "FORBID")
    at = VoiceAttestor()
    seal_entailment_commitment(at, EntailmentCommitment())
    assert at.records()[0].payload["verdict"] == NO_VERDICT_MARKER


def test_sealed_vocabulary_never_overpromises(tmp_path: Path) -> None:
    # The words that would claim the unbuilt half. THRESHOLD_LABEL is the one
    # sanctioned exception: it may say "coverage" ONLY inside the negation
    # "no proven coverage" (voice_gate.py:64-67), and never the other two.
    banned = ("guarantee", "1-alpha")
    assert all(word not in THRESHOLD_LABEL.casefold() for word in banned)
    label = THRESHOLD_LABEL.casefold()
    assert label.count("coverage") == label.count("no proven coverage") == 1

    path, digest = _write_nli_corpus(tmp_path)
    at = VoiceAttestor()
    seal_entailment_commitment(at, commitment_from_corpus(load_corpus(path), corpus_sha256=digest))
    sealed = _stable_json(at.records()[0].payload).casefold()
    scrubbed = sealed.replace(THRESHOLD_LABEL.casefold(), "")
    for word in (*banned, "coverage"):
        assert word not in scrubbed, f"sealed payload claims {word!r}"
    # "entailment certificate" language: the artifact never even calls itself
    # a certificate — it is a commitment, and says so.
    assert "certificate" not in sealed
    assert GATE_COMMITMENT_KEY in at.records()[0].payload["gate"]


def test_error_messages_do_not_overpromise() -> None:
    messages: list[str] = []
    base = dict(points=(), n_calibration=None, provenance=None, verification=None)
    for build in (
        lambda: commitment_from_corpus(
            LoadedCorpus(consumer="nli", corpus_id="x", kind="field", **base),
            corpus_sha256="0" * 64,
        ),
        lambda: EntailmentCommitment(calibrated=True),
        lambda: EntailmentCommitment(lambda_hat=0.7),
    ):
        with pytest.raises(Exception) as excinfo:  # noqa: PT011 — message scan, not type pin
            build()
        messages.append(str(excinfo.value).casefold())
    for msg in messages:
        for word in ("guarantee", "coverage", "1-alpha"):
            assert word not in msg, f"error message claims {word!r}: {msg}"


def test_a_model_construct_forged_calibrated_true_is_rejected_at_replay() -> None:
    # pydantic's model_construct() skips validation — an in-process liar can
    # BUILD a calibrated=True object and seal its dump. Replay must refuse it:
    # the verifier re-validates every embedded commitment against schema v1.
    forged = EntailmentCommitment.model_construct(
        schema_version=COMMITMENT_SCHEMA,
        model_id=MODEL_A,
        model_loaded=False,
        threshold_label=THRESHOLD_LABEL,
        lambda_hat=0.87,
        calibrated=True,
        calibration_manifest_sha256=None,
        calibration_corpus_id=None,
        calibration_corpus_kind=None,
        created_at="2026-06-11T00:00:00+00:00",
    )
    with warnings.catch_warnings():
        # The forge's dump legitimately mismatches the schema — that IS the
        # attack; silence pydantic's serializer note for this deliberate act.
        warnings.simplefilter("ignore", UserWarning)
        forged_dump = forged.model_dump()
        forged_hash = forged.commitment_sha256()
    at = VoiceAttestor()
    at.seal(
        transcript="",
        routed_dimension="entailment-commitment",
        verdict=NO_VERDICT_MARKER,
        answer="",
        object_=None,
        proof_ref=None,
        gate={
            GATE_COMMITMENT_KEY: forged_dump,
            GATE_COMMITMENT_HASH_KEY: forged_hash,
        },
    )
    res = verify_entailment_commitment(at.records(), expected_model_id=MODEL_A)
    assert res.chain_intact is True  # the chain is honest about what was sealed…
    assert res.commitment_hashes_ok is False  # …but the CLAIM does not validate
    assert res.ok is False
    assert any(i.startswith("commitment_payload_invalid_at:0") for i in res.issues)


# ── hash discipline ──────────────────────────────────────────────────────────


def test_commitment_hash_is_deterministic_and_binds_every_field() -> None:
    c = EntailmentCommitment(created_at="2026-06-11T00:00:00+00:00")
    assert c.commitment_sha256() == hashlib.sha256(c.canonical_bytes()).hexdigest()
    same = EntailmentCommitment(created_at="2026-06-11T00:00:00+00:00")
    assert c.commitment_sha256() == same.commitment_sha256()
    other = EntailmentCommitment(created_at="2026-06-11T00:00:01+00:00")
    assert c.commitment_sha256() != other.commitment_sha256()


def test_verification_of_an_empty_or_commitment_free_chain_is_not_ok() -> None:
    res = verify_entailment_commitment((), expected_model_id=MODEL_A)
    assert res.ok is False and "no_entailment_commitment_in_records" in res.issues
    at = VoiceAttestor()
    at.seal(
        transcript="q",
        routed_dimension="evidence",
        verdict="ABSTAIN",
        answer="I can't prove that.",
        object_=None,
        proof_ref=None,
        gate={"scorer": "router", "reason": "no-sealed-fact"},
    )
    res = verify_entailment_commitment(at.records(), expected_model_id=MODEL_A)
    assert res.chain_intact is True  # the chain is fine; the COMMITMENT is absent
    assert res.ok is False and "no_entailment_commitment_in_records" in res.issues


def test_schema_pin_is_part_of_the_sealed_bytes() -> None:
    c = EntailmentCommitment()
    assert c.schema_version == COMMITMENT_SCHEMA
    assert COMMITMENT_SCHEMA.encode("utf-8") in c.canonical_bytes()
