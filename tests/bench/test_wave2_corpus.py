"""
Gate for the Wave 2 / M0b calibration-corpus harness (tex.bench.wave2_corpus).

The load-bearing battery is the PROVENANCE GATE: today the consumer contracts
accept ``corpus_kind="field"`` as an honor-system string, and M0b's claim is
that the loader makes that label EARNED — emitted only when a sealed
field-collection attestation verifies against a PINNED key and binds by
SHA-256 to the exact corpus bytes. Every test here is written so it FAILS if
the gate is weakened: a forged/upgraded provenance record that loads, a
synthetic corpus that reaches "field", a tamper that slips through, or a
certificate whose kind was typed rather than earned is the failure mode.

Perf: corpus sizes respect the exact-``math.comb`` envelope (calibration
n <= 400 throughout; the action-class corpus uses the in-tree 300/200 split).
"""

from __future__ import annotations

import inspect
import math

import pytest

from tex.bench.evidence_bundle import (
    forge_record_by_resigning,
    read_bundle,
    trusted_public_key_b64,
    write_bundle,
)
from tex.bench.replay_trial import run_seeded_neighborhood_trial
from tex.bench.wave2_corpus import builders as builders_module
from tex.bench.wave2_corpus import (
    CorpusProvenanceError,
    GATE_OUTCOMES,
    KIND_FIELD,
    KIND_SYNTHETIC,
    NLI_LABELS,
    as_qif_samples,
    attest_field_provenance,
    build_action_class_points,
    build_certifiable_action_class_points,
    build_neighborhood_texts,
    build_nli_pairs,
    build_qif_redteam_points,
    certify_action_class_corpus,
    certify_action_class_from_artifact,
    clopper_pearson_minimum_n,
    corpus_digest,
    corpus_id_for,
    load_corpus,
    minimum_field_corpus_size,
    qif_certificate_from_corpus,
    run_field_neighborhood_trial,
    seal_provenance,
    synthetic_provenance,
    verify_sealed_provenance,
    write_corpus,
)
from tex.bench.wave2_corpus.provenance import SYNTHETIC_METHOD
from tex.contracts.action_class import ActionClassCase
from tex.domain.verdict import Verdict
from tex.engine.crc_gate import hoeffding_bentkus_ucb
from tex.engine.verdict_certificate import (
    NEIGHBORHOOD_FAMILY,
    QIFSample,
    RobustnessObservation,
    certify_verdict,
    stability_p_low,
)
from tex.evidence.seal import build_evidence_chain_signer

_SEED = 20260611


def _signer(tmp_path):
    return build_evidence_chain_signer(key_dir=tmp_path / "keys")


def _write_synthetic_artifact(tmp_path, *, consumer, points, seed, n_calibration=None):
    """The standard builder pipeline: corpus + sealed SYNTHETIC provenance."""
    cid = corpus_id_for(consumer, seed=seed, n_points=len(points))
    corpus_path = tmp_path / f"{consumer}.jsonl"
    digest = write_corpus(
        points, consumer=consumer, corpus_id=cid, path=corpus_path,
        n_calibration=n_calibration,
    )
    signer = _signer(tmp_path)
    prov = synthetic_provenance(
        corpus_id=cid, consumer=consumer, corpus_sha256=digest,
        n_points=len(points), generator_seed=seed,
    )
    bundle_path = tmp_path / f"{consumer}.prov.jsonl"
    seal_provenance(prov, signer=signer, bundle_path=bundle_path)
    return corpus_path, bundle_path, signer, cid


def _write_field_artifact(tmp_path, *, consumer, points, name="field"):
    """A SIMULATED field artifact: test fixture attested by a test collector.

    This exercises the attestation MECHANISM; the texts themselves are not
    real field data (none exists yet — that is M0b's documented BLOCKED item).
    """
    cid = f"{name}.test.v1"
    corpus_path = tmp_path / f"{name}.jsonl"
    digest = write_corpus(points, consumer=consumer, corpus_id=cid, path=corpus_path)
    signer = _signer(tmp_path)
    prov = attest_field_provenance(
        corpus_id=cid, consumer=consumer, corpus_sha256=digest, n_points=len(points),
        collector="test-collector (simulated field fixture)",
        collection_method="pytest fixture attestation — NOT a real collection",
        source_description="simulated attacker paraphrases for gate testing",
        window_start="2026-06-01", window_end="2026-06-10",
    )
    bundle_path = tmp_path / f"{name}.prov.jsonl"
    seal_provenance(prov, signer=signer, bundle_path=bundle_path)
    return corpus_path, bundle_path, signer, cid


# ── 1. determinism + exact consumer types + round-trip ─────────────────────


def test_builders_deterministic_and_seed_sensitive() -> None:
    assert build_action_class_points(seed=_SEED) == build_action_class_points(seed=_SEED)
    assert build_neighborhood_texts(seed=_SEED, n_samples=30) == build_neighborhood_texts(
        seed=_SEED, n_samples=30
    )
    assert build_qif_redteam_points(seed=_SEED, n_points=60) == build_qif_redteam_points(
        seed=_SEED, n_points=60
    )
    assert build_nli_pairs(seed=_SEED, n_per_class=12) == build_nli_pairs(
        seed=_SEED, n_per_class=12
    )
    # A different seed must actually move the corpus (no silent constant).
    assert build_qif_redteam_points(seed=_SEED + 1, n_points=60) != build_qif_redteam_points(
        seed=_SEED, n_points=60
    )
    assert build_nli_pairs(seed=_SEED + 1, n_per_class=12) != build_nli_pairs(
        seed=_SEED, n_per_class=12
    )


def test_builders_emit_exact_consumer_types() -> None:
    cal, hold = build_action_class_points(seed=_SEED)
    assert all(isinstance(c, ActionClassCase) for c in cal + hold)
    samples = as_qif_samples(build_qif_redteam_points(seed=_SEED, n_points=20))
    assert all(isinstance(s, QIFSample) for s in samples)
    assert all(s.verdict in {v.value for v in Verdict} for s in samples)


def test_write_load_roundtrip_is_exact_and_byte_deterministic(tmp_path) -> None:
    cal, hold = build_action_class_points(seed=_SEED)
    points = cal + hold
    cid = corpus_id_for("action_class", seed=_SEED, n_points=len(points))
    d1 = write_corpus(points, consumer="action_class", corpus_id=cid,
                      path=tmp_path / "a.jsonl", n_calibration=len(cal))
    d2 = write_corpus(points, consumer="action_class", corpus_id=cid,
                      path=tmp_path / "b.jsonl", n_calibration=len(cal))
    assert d1 == d2 == corpus_digest(tmp_path / "a.jsonl")
    loaded = load_corpus(tmp_path / "a.jsonl")
    assert loaded.points == points          # exact round-trip
    assert loaded.n_calibration == len(cal)
    assert loaded.kind == "synthetic"       # no provenance -> synthetic only


def test_nli_roundtrip_and_closed_world_decode(tmp_path) -> None:
    pairs = build_nli_pairs(seed=_SEED, n_per_class=10)
    cid = corpus_id_for("nli", seed=_SEED, n_points=len(pairs))
    path = tmp_path / "nli.jsonl"
    write_corpus(pairs, consumer="nli", corpus_id=cid, path=path)
    assert load_corpus(path).points == pairs
    # An out-of-vocabulary label in the file must be refused at decode.
    corrupted = path.read_text(encoding="utf-8").replace(
        '"label":"entailed"', '"label":"maybe"', 1
    )
    bad = tmp_path / "nli_bad.jsonl"
    bad.write_text(corrupted, encoding="utf-8")
    with pytest.raises(ValueError, match="closed world"):
        load_corpus(bad)


# ── 2. the provenance gate ──────────────────────────────────────────────────


def test_synthetic_pipeline_never_reaches_field_even_with_pin(tmp_path) -> None:
    """Every builder's standard pipeline loads as synthetic — with the pin."""
    fixtures = (
        ("action_class", sum(build_action_class_points(seed=_SEED), ())),
        ("neighborhood", build_neighborhood_texts(seed=_SEED, n_samples=25)),
        ("qif_redteam", build_qif_redteam_points(seed=_SEED, n_points=40)),
        ("nli", build_nli_pairs(seed=_SEED, n_per_class=8)),
    )
    for consumer, points in fixtures:
        sub = tmp_path / consumer
        sub.mkdir()
        corpus_path, bundle_path, signer, _ = _write_synthetic_artifact(
            sub, consumer=consumer, points=tuple(points), seed=_SEED
        )
        loaded = load_corpus(
            corpus_path,
            provenance_bundle=bundle_path,
            pinned_public_key_b64=trusted_public_key_b64(signer),
        )
        assert loaded.kind == "synthetic", consumer
        assert loaded.provenance is not None
        assert loaded.provenance.corpus_kind == KIND_SYNTHETIC


def test_field_label_requires_attestation_pin_and_binding(tmp_path) -> None:
    texts = build_neighborhood_texts(seed=_SEED, n_samples=30)
    corpus_path, bundle_path, signer, _ = _write_field_artifact(
        tmp_path, consumer="neighborhood", points=list(texts)
    )
    pin = trusted_public_key_b64(signer)
    loaded = load_corpus(corpus_path, provenance_bundle=bundle_path,
                         pinned_public_key_b64=pin)
    assert loaded.kind == "field"
    assert loaded.provenance is not None
    assert loaded.provenance.corpus_kind == KIND_FIELD
    # Without the pin, authorship is UNVERIFIED -> the label is refused loudly.
    with pytest.raises(CorpusProvenanceError, match="pinned public key"):
        load_corpus(corpus_path, provenance_bundle=bundle_path)


def test_byteflip_in_corpus_file_breaks_the_binding(tmp_path) -> None:
    texts = build_neighborhood_texts(seed=_SEED, n_samples=20)
    corpus_path, bundle_path, signer, _ = _write_field_artifact(
        tmp_path, consumer="neighborhood", points=list(texts)
    )
    pin = trusted_public_key_b64(signer)
    lines = corpus_path.read_text(encoding="utf-8").splitlines()
    # Flip one character INSIDE the first data point (never the manifest, so
    # the failure exercised is the digest binding, not schema parsing).
    point = lines[1]
    idx = point.index('"text":"') + len('"text":"')
    flipped = "X" if point[idx] != "X" else "Y"
    lines[1] = point[:idx] + flipped + point[idx + 1 :]
    corpus_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    with pytest.raises(CorpusProvenanceError, match="corpus_digest_mismatch"):
        load_corpus(corpus_path, provenance_bundle=bundle_path,
                    pinned_public_key_b64=pin)


def test_byteflip_in_provenance_bundle_breaks_integrity(tmp_path) -> None:
    texts = build_neighborhood_texts(seed=_SEED, n_samples=20)
    corpus_path, bundle_path, signer, _ = _write_field_artifact(
        tmp_path, consumer="neighborhood", points=list(texts)
    )
    pin = trusted_public_key_b64(signer)
    record = read_bundle(bundle_path)[0]
    edited = record.payload_json.replace("test-collector", "Test-collector", 1)
    assert edited != record.payload_json
    bad = record.model_copy(update={"payload_json": edited})
    write_bundle([bad], bundle_path)
    with pytest.raises(CorpusProvenanceError):
        load_corpus(corpus_path, provenance_bundle=bundle_path,
                    pinned_public_key_b64=pin)
    v = verify_sealed_provenance(bundle_path,
                                 corpus_sha256=corpus_digest(corpus_path))
    assert not v.integrity_ok
    assert not v.field_earned


def test_resign_forgery_upgrading_synthetic_to_field_is_caught_by_pin(tmp_path) -> None:
    """THE attack M0b exists to stop: synthetic data re-attested as 'field'.

    The adversary takes a legitimate synthetic artifact, rewrites its sealed
    provenance to claim a field collection, and re-signs with their own key,
    keeping the record internally consistent. Integrity PASSES (the bundle
    self-verifies); the parsed claim is a perfectly well-formed field record;
    the digest still binds. Only the Tex key pin catches it — and the loader
    refuses the artifact both with the pin (authorship fails) and without it
    (a field claim without a pin is never accepted). Mirrors the replay
    trial's tamper-then-resign probe.
    """
    texts = build_neighborhood_texts(seed=_SEED, n_samples=20)
    corpus_path, bundle_path, signer, _ = _write_synthetic_artifact(
        tmp_path, consumer="neighborhood", points=texts, seed=_SEED
    )
    pin = trusted_public_key_b64(signer)
    record = read_bundle(bundle_path)[0]
    adversary = build_evidence_chain_signer(key_dir=tmp_path / "_adv_keys")
    forged = forge_record_by_resigning(
        record,
        mutate=lambda p: {
            **p,
            "corpus_kind": KIND_FIELD,
            "collection_method": "definitely real fieldwork",
            "collector": "adversary",
            "generator_seed": None,
        },
        adversary_signer=adversary,
    )
    write_bundle([forged], bundle_path)

    # The forgery is internally consistent: integrity passes unpinned...
    unpinned = verify_sealed_provenance(
        bundle_path, corpus_sha256=corpus_digest(corpus_path)
    )
    assert unpinned.integrity_ok
    assert unpinned.provenance is not None
    assert unpinned.provenance.corpus_kind == KIND_FIELD  # the lie parses
    assert unpinned.digest_matches
    assert not unpinned.field_earned  # ...but the label is NOT earned without the pin

    # ...and the loader refuses it both ways.
    with pytest.raises(CorpusProvenanceError, match="pin"):
        load_corpus(corpus_path, provenance_bundle=bundle_path,
                    pinned_public_key_b64=pin)
    with pytest.raises(CorpusProvenanceError, match="pinned public key"):
        load_corpus(corpus_path, provenance_bundle=bundle_path)


def test_field_provenance_is_unconstructible_from_builder_paths(tmp_path) -> None:
    """Structural unreachability, not vigilance.

    (a) the synthetic constructor has no kind parameter to abuse;
    (b) the model rejects every synthetic/field field-mix a fabricator needs;
    (c) the builders module never references the attestation entry point
        (source tripwire — fails if someone wires it in later).
    """
    with pytest.raises(TypeError):
        synthetic_provenance(  # type: ignore[call-arg]
            corpus_id="x", consumer="nli", corpus_sha256="0" * 64, n_points=1,
            generator_seed=1, corpus_kind=KIND_FIELD,
        )
    # Field provenance must not carry the reserved generator method...
    with pytest.raises(ValueError, match="reserved synthetic-generator"):
        attest_field_provenance(
            corpus_id="x", consumer="nli", corpus_sha256="0" * 64, n_points=1,
            collector="someone", collection_method=SYNTHETIC_METHOD,
            source_description="s", window_start="2026-06-01", window_end="2026-06-02",
        )
    # ...nor a generator seed (a generated corpus is not a collection).
    from tex.bench.wave2_corpus.provenance import CorpusProvenance
    with pytest.raises(ValueError, match="generator_seed"):
        CorpusProvenance(
            corpus_id="x", corpus_kind=KIND_FIELD, consumer="nli",
            corpus_sha256="0" * 64, n_points=1, collector="c",
            collection_method="m", source_description="s",
            window_start="2026-06-01", window_end="2026-06-02", generator_seed=7,
        )
    source = inspect.getsource(builders_module)
    assert "attest_field_provenance" not in source


def test_provenance_contradicting_manifest_is_refused(tmp_path) -> None:
    texts = build_neighborhood_texts(seed=_SEED, n_samples=20)
    cid = corpus_id_for("neighborhood", seed=_SEED, n_points=len(texts))
    corpus_path = tmp_path / "nb.jsonl"
    digest = write_corpus(texts, consumer="neighborhood", corpus_id=cid, path=corpus_path)
    signer = _signer(tmp_path)
    prov = synthetic_provenance(
        corpus_id="some-other-corpus.v1", consumer="neighborhood",
        corpus_sha256=digest, n_points=len(texts), generator_seed=_SEED,
    )
    bundle_path = tmp_path / "nb.prov.jsonl"
    seal_provenance(prov, signer=signer, bundle_path=bundle_path)
    with pytest.raises(CorpusProvenanceError, match="contradicts"):
        load_corpus(corpus_path, provenance_bundle=bundle_path,
                    pinned_public_key_b64=trusted_public_key_b64(signer))


# ── 3. L4: certification with an EARNED kind ────────────────────────────────


def test_l4_synthetic_corpus_stays_certified_false(tmp_path) -> None:
    cal, hold = build_action_class_points(seed=_SEED)
    corpus_path, bundle_path, signer, _ = _write_synthetic_artifact(
        tmp_path, consumer="action_class", points=cal + hold, seed=_SEED,
        n_calibration=len(cal),
    )
    loaded = load_corpus(corpus_path, provenance_bundle=bundle_path,
                         pinned_public_key_b64=trusted_public_key_b64(signer))
    cert = certify_action_class_corpus(loaded)
    assert cert.enabled is True
    assert cert.corpus_kind == "synthetic"   # flowed from the gate, not typed
    assert cert.certified is False           # synthetic computes-but-abstains
    assert cert.certified_under_classification_rate == 1.0


def test_l4_anti_circularity_tripwire_fires_on_circular_corpus(tmp_path) -> None:
    """Ground truth derived FROM the declared steps -> zero genuine misses ->
    the bound is vacuous and certification must be refused, not minted."""
    cal, hold = build_action_class_points(seed=_SEED)
    circular = tuple(
        ActionClassCase(
            declared_steps=c.declared_steps,
            # the circular sin: truth recomputed from the declaration
            ground_truth_must_forbid=c.predicted().name == "FORBID",
        )
        for c in cal + hold
    )
    cid = "circular.test.v1"
    corpus_path = tmp_path / "circ.jsonl"
    write_corpus(circular, consumer="action_class", corpus_id=cid,
                 path=corpus_path, n_calibration=len(cal))
    loaded = load_corpus(corpus_path)
    with pytest.raises(CorpusProvenanceError, match="anti-circularity"):
        certify_action_class_corpus(loaded)


def test_l4_field_kind_flows_but_arithmetic_still_decides(tmp_path) -> None:
    """A field-attested L4 corpus with a high miss rate must NOT certify:
    the label opens the gate, the Hoeffding-Bentkus arithmetic still rules."""
    cal, hold = build_action_class_points(seed=_SEED)  # p_under=0.5 >> alpha
    cid = "l4field.split.v1"
    corpus_path = tmp_path / "l4field.jsonl"
    digest = write_corpus(cal + hold, consumer="action_class", corpus_id=cid,
                          path=corpus_path, n_calibration=len(cal))
    signer = _signer(tmp_path)
    prov = attest_field_provenance(
        corpus_id=cid, consumer="action_class", corpus_sha256=digest,
        n_points=len(cal + hold),
        collector="test-collector (simulated field fixture)",
        collection_method="pytest fixture attestation — NOT a real collection",
        source_description="simulated incident-outcome labels for gate testing",
        window_start="2026-06-01", window_end="2026-06-10",
    )
    bundle_path = tmp_path / "l4field.prov.jsonl"
    seal_provenance(prov, signer=signer, bundle_path=bundle_path)
    loaded = load_corpus(corpus_path, provenance_bundle=bundle_path,
                         pinned_public_key_b64=trusted_public_key_b64(signer))
    assert loaded.kind == "field"
    cert = certify_action_class_corpus(loaded)
    assert cert.corpus_kind == "field"
    # honest arithmetic: empirical under-rate ~0.15 >> alpha=0.05 -> no cert.
    assert cert.under_risk_upper_bound > cert.alpha
    assert cert.certified is False


def test_l4_field_corpus_certifies_through_earned_label(tmp_path) -> None:
    """SIMULATED-field L4 dry run: attest -> seal -> load(gate) -> certify=True.

    The CERTIFIED counterpart of the test above. That corpus (default builder,
    p_under=0.50) has a high miss rate whose UCB never clears alpha. This one uses
    ``build_certifiable_action_class_points``: a LOW mis-declaration rate over a
    LARGE holdout, so the calibration UCB clears alpha (the bound gate) AND the
    holdout still carries >= 20 genuine misses (the anti-vacuity tripwire) — so
    BOTH L4 gates clear and the EARNED 'field' label flips certified=True.

    The labels are simulated (no real L4 field corpus exists yet — the documented
    BLOCKED item, see NOTES.md). What this proves is the WIRING: had the loader,
    the pin, the SHA-256 binding, the holdout tripwire, or the Hoeffding-Bentkus
    arithmetic been weakened, this exact path is where it would show. It is the L4
    analog of ``test_field_trial_end_to_end_against_live_runtime`` (L12).
    """
    cal, hold = build_certifiable_action_class_points()  # seed=20260618
    points = cal + hold
    cid = "l4.certifiable.field.test.v1"
    corpus_path = tmp_path / "l4cert.jsonl"
    digest = write_corpus(points, consumer="action_class", corpus_id=cid,
                          path=corpus_path, n_calibration=len(cal))
    signer = _signer(tmp_path)
    prov = attest_field_provenance(
        corpus_id=cid, consumer="action_class", corpus_sha256=digest,
        n_points=len(points),
        collector="test-collector (simulated field fixture)",
        collection_method="pytest fixture attestation — NOT a real collection",
        source_description="simulated incident-outcome action-class labels for gate testing",
        window_start="2026-06-01", window_end="2026-06-10",
    )
    bundle_path = tmp_path / "l4cert.prov.jsonl"
    seal_provenance(prov, signer=signer, bundle_path=bundle_path)
    pin = trusted_public_key_b64(signer)

    loaded, cert = certify_action_class_from_artifact(
        corpus_path, provenance_bundle=bundle_path, pinned_public_key_b64=pin
    )
    assert loaded.kind == "field"                  # earned through the gate
    assert cert.corpus_kind == "field"
    assert cert.certified is True                  # THE flip, through the earned label
    assert cert.under_risk_upper_bound <= cert.alpha
    assert cert.certified_under_classification_rate == cert.under_risk_upper_bound
    assert cert.n_calibration == len(cal)

    # Offline re-check: a fresh load from the same bytes + bundle + pin re-derives
    # the IDENTICAL certificate (deterministic, no runtime) — the auditor's replay.
    _loaded2, cert2 = certify_action_class_from_artifact(
        corpus_path, provenance_bundle=bundle_path, pinned_public_key_b64=pin
    )
    assert cert2.model_dump() == cert.model_dump()

    # The honesty gate still holds at the artifact boundary:
    #  - a field claim without the pin is refused (authorship UNVERIFIED);
    with pytest.raises(CorpusProvenanceError, match="pinned public key"):
        certify_action_class_from_artifact(corpus_path, provenance_bundle=bundle_path)
    #  - the SAME bytes with no provenance load synthetic and never certify.
    synth_loaded, synth_cert = certify_action_class_from_artifact(corpus_path)
    assert synth_loaded.kind == "synthetic"
    assert synth_cert.certified is False
    assert synth_cert.certified_under_classification_rate == 1.0


# ── 4. L12: the field entry point + pinned gate arithmetic ──────────────────


def test_field_trial_refuses_synthetic_corpora(tmp_path) -> None:
    texts = build_neighborhood_texts(seed=_SEED, n_samples=20)
    corpus_path, bundle_path, signer, _ = _write_synthetic_artifact(
        tmp_path, consumer="neighborhood", points=texts, seed=_SEED
    )
    loaded = load_corpus(corpus_path, provenance_bundle=bundle_path,
                         pinned_public_key_b64=trusted_public_key_b64(signer))
    with pytest.raises(ValueError, match="field"):
        run_field_neighborhood_trial(object(), corpus=loaded)


def test_field_trial_end_to_end_against_live_runtime(runtime, tmp_path) -> None:
    """SIMULATED-field e2e: attest -> seal -> load(gate) -> live PDP -> certify.

    78 is the verified minimum n at alpha=delta=0.05 (see sizing tests). The
    structural action graph forces FORBID on every text, so 78/78 stable ->
    stored p_low = 0.950062 >= 0.95 -> certified=True THROUGH THE EARNED
    LABEL. The texts are simulated (a real field corpus does not exist yet);
    what this test proves is the mechanism: had the loader, the binding, the
    pin, or the arithmetic been weakened, this exact path is where it shows.
    """
    texts = build_neighborhood_texts(seed=_SEED, n_samples=78)
    corpus_path, bundle_path, signer, cid = _write_field_artifact(
        tmp_path, consumer="neighborhood", points=list(texts)
    )
    loaded = load_corpus(corpus_path, provenance_bundle=bundle_path,
                         pinned_public_key_b64=trusted_public_key_b64(signer))
    res = run_field_neighborhood_trial(runtime, corpus=loaded)
    assert res.n_samples == 78
    assert res.n_stable == 78  # structural FORBID is content-invariant
    assert res.certificate.robustness_neighborhood_kind == "field"
    assert res.certificate.certified is True
    assert res.certificate.robustness_stability_p_low >= 0.95
    # The family names the MEASURED corpus, never the synthetic ops string.
    assert res.family != NEIGHBORHOOD_FAMILY
    assert cid in res.family
    assert "test-collector" in res.family
    assert res.certificate.robustness_family == res.family


def test_l12_gate_arithmetic_pinned_to_closed_form() -> None:
    """At zero instability the in-tree bound is Bentkus: p_low=(delta/e)^(1/n).
    n=78 clears 1-alpha, n=77 does not — pinned against the independent
    closed form so a drift in the bound (or the floored-stored gate) fails here."""
    delta = alpha = 0.05
    closed_form_78 = (delta / math.e) ** (1.0 / 78.0)
    assert stability_p_low(78, 78, delta) == pytest.approx(closed_form_78, abs=1e-6)
    assert stability_p_low(78, 78, delta) >= 1 - alpha
    assert stability_p_low(77, 77, delta) < 1 - alpha

    def field_obs(n: int) -> RobustnessObservation:
        return RobustnessObservation(
            n_samples=n, n_stable=n, delta=delta, seed=1,
            family="field-corpus test family", neighborhood_kind="field",
        )

    assert certify_verdict(robustness=field_obs(78), alpha=alpha).certified is True
    assert certify_verdict(robustness=field_obs(77), alpha=alpha).certified is False
    # The synthetic kind computes the same number but can never certify.
    synth = RobustnessObservation(
        n_samples=78, n_stable=78, delta=delta, seed=1,
        family=NEIGHBORHOOD_FAMILY, neighborhood_kind="synthetic",
    )
    assert certify_verdict(robustness=synth, alpha=alpha).certified is False


def test_minimum_corpus_sizes_match_in_tree_bound() -> None:
    n_hb = minimum_field_corpus_size(0.05, 0.05)
    assert n_hb == 78
    assert hoeffding_bentkus_ucb(0.0, n_hb, 0.05) <= 0.05
    assert hoeffding_bentkus_ucb(0.0, n_hb - 1, 0.05) > 0.05
    assert clopper_pearson_minimum_n(0.05, 0.05) == 59
    assert (1 - 0.05) ** 59 <= 0.05 < (1 - 0.05) ** 58


def test_synthetic_seeded_trial_label_is_untouched(runtime) -> None:
    """The separate-entry-point contract: the seeded trial still says synthetic."""
    res = run_seeded_neighborhood_trial(runtime, seed=_SEED, n_samples=10)
    assert res.certificate.robustness_neighborhood_kind == "synthetic"
    assert res.certificate.certified is False


# ── 5. QIF / CRC red-team corpus ────────────────────────────────────────────


def test_qif_corpus_kind_flows_from_gate_and_never_certifies(tmp_path) -> None:
    points = build_qif_redteam_points(seed=_SEED, n_points=120, coupling=0.7)
    corpus_path, bundle_path, signer, _ = _write_synthetic_artifact(
        tmp_path, consumer="qif_redteam", points=points, seed=_SEED
    )
    loaded = load_corpus(corpus_path, provenance_bundle=bundle_path,
                         pinned_public_key_b64=trusted_public_key_b64(signer))
    cert = qif_certificate_from_corpus(loaded)
    assert cert.qif_corpus_kind == "synthetic"
    assert cert.qif_certified is False          # pinned Literal[False]
    assert cert.certified is False              # QIF alone can never certify
    assert cert.qif_n_samples == 120
    assert 0.0 <= cert.qif_l_bits_point_estimate <= cert.qif_capacity_ceiling_bits

    # Even a (simulated) FIELD QIF corpus must not flip `certified` — only the
    # robustness half can, and there is none here.
    sub = tmp_path / "fieldqif"
    sub.mkdir()
    fpath, fbundle, fsigner, _ = _write_field_artifact(
        sub, consumer="qif_redteam", points=points, name="qiffield"
    )
    floaded = load_corpus(fpath, provenance_bundle=fbundle,
                          pinned_public_key_b64=trusted_public_key_b64(fsigner))
    fcert = qif_certificate_from_corpus(floaded)
    assert fcert.qif_corpus_kind == "field"
    assert fcert.certified is False
    assert fcert.qif_certified is False


def test_qif_coupling_moves_the_estimate_in_the_right_direction() -> None:
    """coupling=0 -> ~independent channel (estimate near 0, plug-in bias only);
    coupling=1 -> deterministic tier map (substantial leakage). If the labels
    stopped reaching the channel, both collapse and this fails."""
    from tex.engine.verdict_certificate import estimate_verdict_channel_leakage

    low = estimate_verdict_channel_leakage(
        as_qif_samples(build_qif_redteam_points(seed=_SEED, n_points=400, coupling=0.0))
    )
    high = estimate_verdict_channel_leakage(
        as_qif_samples(build_qif_redteam_points(seed=_SEED, n_points=400, coupling=1.0))
    )
    assert high.shannon_mi_bits > low.shannon_mi_bits + 0.3
    assert high.min_entropy_leakage_bits > low.min_entropy_leakage_bits
    assert low.shannon_mi_bits < 0.1  # independent channel: bias only


def test_qif_points_carry_fides_tags() -> None:
    from tex.governance.private_data_exec.ifc.capability_compat import (
        CapabilityLevel,
        ConfidentialityLevel,
    )

    points = build_qif_redteam_points(seed=_SEED, n_points=150)
    tiers = {p.confidentiality for p in points}
    assert tiers == set(ConfidentialityLevel.__members__)  # all four present
    assert all(p.secret_label == p.confidentiality for p in points)
    assert all(p.integrity in CapabilityLevel.__members__ for p in points)
    # the canonical FIDES violation pair must be represented in a red-team corpus
    assert any(
        p.integrity == "UNTRUSTED" and ConfidentialityLevel[p.confidentiality].is_sensitive
        for p in points
    )


# ── 6. NLI pairs: closed world, positives free, negatives present ───────────


def test_nli_closed_world_and_all_classes_present() -> None:
    pairs = build_nli_pairs(seed=_SEED, n_per_class=15)
    assert {p.label for p in pairs} == set(NLI_LABELS)
    assert {p.gate_outcome for p in pairs} == set(GATE_OUTCOMES)
    by_outcome = {o: [p for p in pairs if p.gate_outcome == o] for o in GATE_OUTCOMES}
    assert all(len(v) == 15 for v in by_outcome.values())
    # alignment: sealed <-> entailed; everything else <-> not-entailed
    assert all(p.label == "entailed" for p in by_outcome["sealed"])
    for outcome in ("unsealed", "contradiction", "unverifiable"):
        assert all(p.label == "not-entailed" for p in by_outcome[outcome])


def test_nli_positives_are_entailed_by_construction() -> None:
    """Mirrors the gate's RULE A reconstruction proof exactly: a template-fill
    positive IS some authored template formatted with the premise's slot bag;
    a value-mutation negative is NOT (one sealed value was altered, so no
    template reconstructs it from the bag)."""
    templates = builders_module._NLI_TEMPLATES
    pairs = build_nli_pairs(seed=_SEED, n_per_class=20)
    for p in pairs:
        bag = dict(item.split("=", 1) for item in p.premise.split("; "))
        candidates = [t for t, needed in templates if set(needed) == set(bag)]
        assert candidates, "premise slot bag matches no authored template"
        reconstructions = {t.format(**bag) for t in candidates}
        if p.source == "template-fill":
            assert p.hypothesis in reconstructions, p
        elif p.source == "value-mutation":
            assert p.hypothesis not in reconstructions, p
