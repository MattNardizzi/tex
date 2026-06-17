#!/usr/bin/env python3
"""
External-anchor demo — prove the provable-age mechanism with ZERO network.

Mints a throwaway local TSA, takes a real gix checkpoint tree-head, anchors it
(in-process), persists the receipt, verifies it OFFLINE against the pinned cert,
and then shows that a forged/altered tree-head is rejected. Exit 0 iff the
genuine anchor verifies AND the forgery is caught.

    python scripts/anchor_demo.py
    python scripts/verify_it_yourself.py --anchor   # same thing, via the wrapper

HONESTY: the demo's TSA is self-issued (``interchange/_local_tsa.py``) — it
proves the *verification logic*, not real time. Real proof-of-age comes from
``scripts/anchor_checkpoint.py`` against the pinned external authority
(freetsa.org, ``anchors/tsa/``). The demo's structure is identical; only the TSA
(and its trust) differ.
"""

from __future__ import annotations

import hashlib
import json
import sys
import tempfile
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_REPO_ROOT / "src"))

from tex.interchange._local_tsa import issue_timestamp_response, mint_local_tsa  # noqa: E402
from tex.interchange.external_anchor import (  # noqa: E402
    CheckpointAnchorRecord,
    anchor_subject_digest,
    verify_anchor_receipt,
)
from tex.interchange.gix import CheckpointPublisher  # noqa: E402


def main() -> int:
    print("=" * 72)
    print("EXTERNAL ANCHOR DEMO — provable age for the evidence chain (offline)")
    print("=" * 72)

    # 1. A real gix checkpoint tree-head over some decision record hashes.
    record_hashes = tuple(hashlib.sha256(f"decision-{i}".encode()).hexdigest() for i in range(7))
    publisher = CheckpointPublisher(
        origin="tex.local/gix-decision-log", read_record_hashes=lambda: record_hashes
    )
    snapshot = publisher.current_signed_checkpoint()
    cp = snapshot.checkpoint
    print(f"\n[1] gix checkpoint: origin={cp.origin} tree_size={cp.tree_size}")
    print(f"    root_hash={cp.root_hash_hex}")

    # 2. Anchor it to an external TSA (here: a self-issued local one — offline).
    tsa = mint_local_tsa()
    digest = anchor_subject_digest(cp.origin, cp.tree_size, cp.root_hash)
    response_der = issue_timestamp_response(digest, tsa, nonce=4242)
    record = CheckpointAnchorRecord.from_response(
        checkpoint=cp,
        signed_note=snapshot.signed_note,
        authority="local-demo-tsa",
        response_der=response_der,
        request_nonce=4242,
    )
    print(f"\n[2] submitted SHA-256(checkpoint note)={digest.hex()[:24]}… to the TSA")

    # 3. Persist the receipt (JSONL) and reload — proves portability.
    with tempfile.TemporaryDirectory() as td:
        store = Path(td) / "checkpoint_anchors.jsonl"
        store.write_text(record.model_dump_json() + "\n", encoding="utf-8")
        reloaded = CheckpointAnchorRecord.model_validate_json(store.read_text().strip())
    print(f"\n[3] persisted + reloaded receipt ({len(record.response_der_b64)} b64 chars)")

    # 4. Verify OFFLINE against the pinned cert.
    ok = verify_anchor_receipt(reloaded, pinned_tsa_cert_der=tsa.ca_pin_der, expected_nonce=4242)
    print(f"\n[4] OFFLINE verification against the pinned TSA cert:")
    print(f"    -> ok={ok.ok}  {ok.summary()}")

    # 5. A forged tree-head must be rejected (the moat: you cannot back-date).
    forged = reloaded.model_copy(update={"root_hash_hex": hashlib.sha256(b"BACKDATED").hexdigest()})
    bad = verify_anchor_receipt(forged, pinned_tsa_cert_der=tsa.ca_pin_der)
    print(f"\n[5] forged tree-head (different root, same receipt):")
    print(f"    -> ok={bad.ok}  failure_code={bad.failure_code}")

    # 6. A token re-signed by an attacker (real cert embedded) must be rejected.
    from cryptography.hazmat.primitives.asymmetric import rsa

    attacker = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    forged_sig = CheckpointAnchorRecord.from_response(
        checkpoint=cp,
        signed_note=None,
        authority="local-demo-tsa",
        response_der=issue_timestamp_response(digest, tsa, sign_key=attacker, gen_time="20200101000000Z"),
    )
    bad_sig = verify_anchor_receipt(forged_sig, pinned_tsa_cert_der=tsa.ca_pin_der)
    print(f"\n[6] back-dated token re-signed by an attacker (real cert embedded):")
    print(f"    -> ok={bad_sig.ok}  failure_code={bad_sig.failure_code}")

    held = ok.ok and (not bad.ok) and (not bad_sig.ok)
    print("\n" + "=" * 72)
    print(f"RESULT: {'ALL CLAIMS HELD' if held else 'A CLAIM FAILED'} "
          f"(genuine verifies={ok.ok}, forged-root rejected={not bad.ok}, "
          f"forged-sig rejected={not bad_sig.ok})")
    print("=" * 72)
    return 0 if held else 1


if __name__ == "__main__":
    raise SystemExit(main())
