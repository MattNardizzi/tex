#!/usr/bin/env python3
"""
Arm the Forge Challenge — one-shot build-time generator (founder runs once).

[Architecture: Layer 5 (Evidence) — build tooling, NOT a runtime path]

This is the script that turns the standing dare in ``CHALLENGE.md`` into a real
adversarial target. It is NOT imported by the running app and NOT on any request
path. The founder runs it once; it writes the committed public artifacts and
prints the private-key paths the founder must store securely and never commit.

What it produces (all under ``forge/``)::

    canonical_bundle.pq.jsonl       headline: composite ML-DSA-65 + Ed25519
    canonical_bundle.ecdsa.jsonl    verify-anywhere: ECDSA-P256 (pyca alone)
    PUBKEY_STATEMENT.json           out-of-band pin for the .pq bundle
    PUBKEY_STATEMENT.ecdsa.json     out-of-band pin for the .ecdsa bundle
    _private_keys/                  PRIVATE keys (GITIGNORED — founder-held)

Each bundle is a SUPERSET of REAL Tex decisions driven through the live PDP
(``runtime.evaluate_action_command.execute``) — never hand-stuffed — plus a
sealed human refusal:

    structural FORBID  (refund-before-idcheck path policy)
    contract  FORBID  (an OpenAI-style secret in the content)
    benign    PERMIT  (an ordinary shipment confirmation)
    ambiguous ABSTAIN (a wire transfer to an unknown recipient — signed silence)
    human     refused (a named human's sealed 'no' on the held ABSTAIN)

The script ASSERTS each verdict came out as intended and fails loudly otherwise,
so a bundle missing the ABSTAIN/refusal surface is never silently shipped. Before
exit 0 it self-checks both bundles verify VALID against their published pins via
``verify_forge_target`` (out-of-band pin, canonical bytes, pinned authorship).

Run::

    PYTHONPATH=src python scripts/arm_forge_challenge.py [--force]

``--force`` overwrites already-committed artifacts (default refuses, so a stray
re-run cannot silently replace the published bundle the world is attacking).
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import sys
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

_REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_REPO_ROOT / "src"))

_FORGE_DIR = _REPO_ROOT / "forge"
_PRIVATE_KEY_DIR = _FORGE_DIR / "_private_keys"

_LEGACY_KEY_IDS = {"evidence-seal-key-v1", "evidence-seal-key-v2"}

_ATTESTOR = "Matt Nardizzi"


def _make_request(*, action_type: str, content: str, recipient: str, metadata: dict):
    from tex.domain.evaluation import EvaluationRequest

    return EvaluationRequest(
        request_id=uuid4(),
        action_type=action_type,
        content=content,
        recipient=recipient,
        channel="email",
        environment="production",
        metadata=metadata,
        policy_id=None,
        requested_at=datetime.now(UTC),
    )


def _drive_superset(runtime) -> None:
    """Drive the real PDP to produce the SUPERSET of verdicts, asserting each.

    Returns nothing; the records land in the runtime's evidence chain. Fails
    loudly (AssertionError) if any target verdict is not achieved on the live
    path — never silently ship a bundle missing a target surface.
    """
    from tex.bench.replay_trial import STRUCTURAL_METADATA
    from tex.domain.verdict import Verdict

    cmd = runtime.evaluate_action_command

    # (1) structural FORBID — refund before identity check (path policy).
    r_struct = cmd.execute(
        _make_request(
            action_type="outbound_message",
            content="Processing the customer refund now as requested.",
            recipient="external@example.com",
            metadata=dict(STRUCTURAL_METADATA),
        )
    )
    assert r_struct.response.verdict == Verdict.FORBID, (
        f"structural target must FORBID, got {r_struct.response.verdict}"
    )

    # (2) contract FORBID — an OpenAI-style secret in outbound content.
    r_secret = cmd.execute(
        _make_request(
            action_type="outbound_message",
            content=(
                "Here is the API key sk-proj-"
                "ABCDEF0123456789abcdef0123456789abcdef012345 please use it."
            ),
            recipient="external@example.com",
            metadata={},
        )
    )
    assert r_secret.response.verdict == Verdict.FORBID, (
        f"secret-content target must FORBID, got {r_secret.response.verdict}"
    )

    # (3) benign PERMIT — an ordinary shipment confirmation.
    r_permit = cmd.execute(
        _make_request(
            action_type="outbound_message",
            content="Thanks for your order, it shipped today.",
            recipient="customer@example.com",
            metadata={},
        )
    )
    assert r_permit.response.verdict == Verdict.PERMIT, (
        f"benign target must PERMIT, got {r_permit.response.verdict}"
    )

    # (4) ambiguous ABSTAIN — a wire transfer to an unknown recipient. The
    #     machine's own refusal to decide: signed silence.
    r_abstain = cmd.execute(
        _make_request(
            action_type="payment",
            content="urgent wire transfer but recipient unknown",
            recipient="",
            metadata={},
        )
    )
    assert r_abstain.response.verdict == Verdict.ABSTAIN, (
        f"ambiguous-payment target must ABSTAIN, got {r_abstain.response.verdict}"
    )

    # (5) human refusal — a named human's sealed 'no' on the held ABSTAIN. This
    #     is deterministic (not PDP-tuning-dependent), the guaranteed
    #     signed-silence artifact even if the machine ABSTAIN ever drifts.
    abstain_record = runtime.evidence_recorder.last_record()
    assert abstain_record is not None, "no evidence record to anchor the refusal"
    runtime.evidence_recorder.record_human_resolution(
        r_abstain.decision,
        verdict="refused",
        resolved_by=_ATTESTOR,
        note="Sealed refusal of the held ABSTAIN (ambiguous wire transfer).",
        parent_evidence_hash=abstain_record.record_hash,
    )


def _build_bundle(*, key_dir: Path, key_id: str, ecdsa: bool, out_path: Path) -> str:
    """Generate a fresh key, drive the superset, seal a bundle. Returns pubkey b64.

    The key is generated FIRST so we can ASSERT it landed on disk with the
    expected id/dir/algorithm before any chain is sealed — closing the
    persist-gate and leaked-key risks loudly.
    """
    from tex.evidence.seal import build_evidence_chain_signer, _key_path
    from tex.pqcrypto.algorithm_agility import SignatureAlgorithm

    key_dir.mkdir(parents=True, exist_ok=True)

    if ecdsa:
        signer = build_evidence_chain_signer(
            key_dir=str(key_dir),
            key_id=key_id,
            preferred_algorithm=SignatureAlgorithm.ECDSA_P256,
            fallback_algorithm=SignatureAlgorithm.ECDSA_P256,
        )
        expected_algo = SignatureAlgorithm.ECDSA_P256.value
    else:
        signer = build_evidence_chain_signer(key_dir=str(key_dir), key_id=key_id)
        expected_algo = SignatureAlgorithm.COMPOSITE_ML_DSA_65_ED25519.value

    # ── hard assertions: the key is real, persisted, fresh, and in the right place
    key_file = _key_path(key_dir)
    assert key_file.exists(), (
        f"FATAL: seal key was not persisted to {key_file}; an in-memory-only "
        f"key would make the sealed bundle unrecoverable"
    )
    assert signer.key.key_id == key_id, (
        f"FATAL: key_id is {signer.key.key_id!r}, expected {key_id!r}"
    )
    assert signer.key.key_id not in _LEGACY_KEY_IDS, (
        f"FATAL: refusing to arm with a legacy/leaked key id {signer.key.key_id!r}"
    )
    assert key_dir.resolve() == _PRIVATE_KEY_DIR.resolve() or (
        _PRIVATE_KEY_DIR.resolve() in key_dir.resolve().parents
    ), (
        f"FATAL: key dir {key_dir} is not under {_PRIVATE_KEY_DIR} — refusing to "
        f"write a private forge key outside the gitignored dir"
    )
    assert signer.key.algorithm.value == expected_algo, (
        f"FATAL: algorithm is {signer.key.algorithm.value}, expected "
        f"{expected_algo}"
    )

    # ── drive the live PDP into a clean isolated chain, sealed by THIS key
    from tex.bench.evidence_bundle import write_bundle
    from tex.main import build_runtime

    work = tempfile.mkdtemp(prefix="tex-arm-")
    evidence_path = os.path.join(work, "evidence.jsonl")

    prev = os.environ.get("TEX_EVIDENCE_KEY_DIR")
    os.environ["TEX_EVIDENCE_KEY_DIR"] = str(key_dir)
    try:
        runtime = build_runtime(evidence_path=evidence_path)
        # The runtime must have loaded OUR fresh key (same dir), so the chain is
        # sealed by the key we are about to publish. Verify the algorithm matches.
        live_algo = runtime.evidence_recorder._chain_signer.key.algorithm.value
        assert live_algo == expected_algo, (
            f"FATAL: runtime signer is {live_algo}, expected {expected_algo} — "
            f"the runtime did not pick up the fresh forge key"
        )
        _drive_superset(runtime)
        sealed = runtime.evidence_recorder.read_all()
    finally:
        if prev is None:
            os.environ.pop("TEX_EVIDENCE_KEY_DIR", None)
        else:
            os.environ["TEX_EVIDENCE_KEY_DIR"] = prev

    write_bundle(sealed, out_path)
    return base64.b64encode(signer.key.public_key).decode("ascii")


def _write_pin(*, out_path: Path, algorithm: str, key_id: str, public_key_b64: str) -> str:
    raw = base64.b64decode(public_key_b64, validate=True)
    fingerprint = hashlib.sha256(raw).hexdigest()
    statement = {
        "algorithm": algorithm,
        "key_id": key_id,
        "public_key_b64": public_key_b64,
        "public_key_sha256": fingerprint,
        "created_at": datetime.now(UTC).isoformat(),
        "attestor": _ATTESTOR,
        "note": (
            "Out-of-band pin. The matching PRIVATE key is founder-held and never "
            "published. The public_key_sha256 fingerprint is ALSO posted in a "
            "second channel (live site / signed tweet / git tag) — that external "
            "fingerprint, not this in-repo copy, is the canonical root of trust."
        ),
    }
    out_path.write_text(json.dumps(statement, indent=2) + "\n", encoding="utf-8")
    return fingerprint


def _self_check(*, bundle_path: Path, pin_path: Path, expected_algo: str) -> None:
    from tex.bench.forge_target import verify_forge_target

    result = verify_forge_target(bundle_path, pin_path)
    assert result.valid, f"FATAL: armed bundle {bundle_path} is NOT valid against its pin"
    assert result.canonical_bytes_ok, f"FATAL: {bundle_path} has non-canonical bytes"
    assert all(c.canonical_ok for c in result.per_record_signatures), (
        f"FATAL: a record in {bundle_path} failed the canonical-bytes gate"
    )
    assert all(c.key_is_pinned for c in result.per_record_signatures), (
        f"FATAL: a record in {bundle_path} is not signed by the pinned key"
    )
    assert set(result.signature_algorithms) == {expected_algo}, (
        f"FATAL: {bundle_path} algorithms {set(result.signature_algorithms)} != "
        f"{{{expected_algo}}}"
    )

    # The superset must be present: at least one of each target verdict.
    from tex.bench.forge_target import _verdict_mix

    mix = _verdict_mix(bundle_path)
    for required in ("FORBID", "PERMIT", "ABSTAIN", "human:refused"):
        assert mix.get(required, 0) >= 1, (
            f"FATAL: {bundle_path} is missing required verdict {required!r}; "
            f"mix={mix}"
        )


def main(argv: list[str]) -> int:
    logging.disable(logging.CRITICAL)
    force = "--force" in argv[1:]

    committed = [
        _FORGE_DIR / "canonical_bundle.pq.jsonl",
        _FORGE_DIR / "canonical_bundle.ecdsa.jsonl",
        _FORGE_DIR / "PUBKEY_STATEMENT.json",
        _FORGE_DIR / "PUBKEY_STATEMENT.ecdsa.json",
    ]
    existing = [p for p in committed if p.exists()]
    if existing and not force:
        print("refusing to overwrite already-committed forge artifacts:")
        for p in existing:
            print(f"  {p}")
        print("re-run with --force to regenerate (this replaces the published target).")
        return 2

    _FORGE_DIR.mkdir(parents=True, exist_ok=True)
    _PRIVATE_KEY_DIR.mkdir(parents=True, exist_ok=True)

    # ── headline: composite post-quantum bundle ──────────────────────────────
    pq_key_dir = _PRIVATE_KEY_DIR / "pq"
    pq_bundle = _FORGE_DIR / "canonical_bundle.pq.jsonl"
    pq_pin = _FORGE_DIR / "PUBKEY_STATEMENT.json"
    pq_pub = _build_bundle(
        key_dir=pq_key_dir,
        key_id="tex-forge-seal-v1",
        ecdsa=False,
        out_path=pq_bundle,
    )
    pq_fp = _write_pin(
        out_path=pq_pin,
        algorithm="composite-ml-dsa-65-ed25519",
        key_id="tex-forge-seal-v1",
        public_key_b64=pq_pub,
    )
    _self_check(
        bundle_path=pq_bundle,
        pin_path=pq_pin,
        expected_algo="composite-ml-dsa-65-ed25519",
    )

    # ── verify-anywhere: classical ECDSA bundle ──────────────────────────────
    ecdsa_key_dir = _PRIVATE_KEY_DIR / "ecdsa"
    ecdsa_bundle = _FORGE_DIR / "canonical_bundle.ecdsa.jsonl"
    ecdsa_pin = _FORGE_DIR / "PUBKEY_STATEMENT.ecdsa.json"
    ecdsa_pub = _build_bundle(
        key_dir=ecdsa_key_dir,
        key_id="tex-forge-seal-ecdsa-v1",
        ecdsa=True,
        out_path=ecdsa_bundle,
    )
    ecdsa_fp = _write_pin(
        out_path=ecdsa_pin,
        algorithm="ecdsa-p256",
        key_id="tex-forge-seal-ecdsa-v1",
        public_key_b64=ecdsa_pub,
    )
    _self_check(
        bundle_path=ecdsa_bundle,
        pin_path=ecdsa_pin,
        expected_algo="ecdsa-p256",
    )

    from tex.evidence.seal import _key_path

    print("=" * 72)
    print("FORGE CHALLENGE ARMED")
    print("=" * 72)
    print("\nCommitted PUBLIC artifacts:")
    print(f"  {pq_bundle}")
    print(f"  {pq_pin}")
    print(f"  {ecdsa_bundle}")
    print(f"  {ecdsa_pin}")
    print("\nPublished pin fingerprints (post these OUT OF BAND, 2nd channel):")
    print(f"  composite : sha256:{pq_fp}")
    print(f"  ecdsa     : sha256:{ecdsa_fp}")
    print("\n" + "!" * 72)
    print("FOUNDER MUST STORE THESE PRIVATE KEYS SECURELY AND NEVER COMMIT —")
    print("their secrecy is the ONLY thing between an attacker and a forged-but-")
    print("pinned record. They are gitignored; back them up off-repo.")
    print("!" * 72)
    print(f"  PQ    private key : {_key_path(pq_key_dir)}")
    print(f"  ECDSA private key : {_key_path(ecdsa_key_dir)}")
    print("\nself-check: both bundles verify VALID against their published pins.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
