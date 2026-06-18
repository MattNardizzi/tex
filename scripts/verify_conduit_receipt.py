#!/usr/bin/env python3
"""
Verify a tex-conduit receipt OFFLINE — without trusting Tex.

A conduit receipt (a sealed directory GRANT, a CONNECTION_DRIFT fact, or an
INVENTORY_SNAPSHOT) is self-describing. This checks, with no network and no
running Tex:

  1. the leaf hash is exactly SHA-256(canonical(payload))   — payload integrity
  2. the leaf is Merkle-included under the checkpoint root   — nothing dropped
  3. the checkpoint note verifies under the log key          — authorship
  4. (if anchored) the RFC 3161 token verifies vs a pinned TSA cert — provable age

Usage::

    python scripts/verify_conduit_receipt.py <receipt.json>
    python scripts/verify_conduit_receipt.py <receipt.json> --pin <pin.json>
    python scripts/verify_conduit_receipt.py <receipt.json> --pin <pin.json> --tsa-cert <ca.der>
    python scripts/verify_conduit_receipt.py --selftest   # seal+verify+tamper, zero args

``--pin`` supplies the log public key out-of-band (the don't-trust-Tex stance):
without it the note is checked against the key embedded in the receipt, which
proves integrity but not authorship. Exit code 0 iff the receipt is valid.
"""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_REPO_ROOT / "src"))

from tex.discovery.conduit.seal import ConduitReceipt  # noqa: E402


def _verify_file(receipt_path: str, pin_path: str | None, tsa_cert_path: str | None) -> int:
    receipt = ConduitReceipt.model_validate_json(Path(receipt_path).read_text(encoding="utf-8"))

    pin_key: str | None = None
    if pin_path:
        pin = json.loads(Path(pin_path).read_text(encoding="utf-8"))
        pin_key = pin["log_public_key_b64"]

    tsa_der: bytes | None = None
    if tsa_cert_path:
        tsa_der = Path(tsa_cert_path).read_bytes()

    result = receipt.verify(pinned_log_public_key_b64=pin_key, pinned_tsa_cert_der=tsa_der)

    print(f"receipt   : {receipt.kind.value}")
    print(f"leaf      : index {receipt.leaf_index} of tree_size {receipt.tree_size}")
    print(f"origin    : {receipt.checkpoint_origin}")
    print(f"leaf hash : {receipt.record_hash_hex}")
    print(f"log key   : {receipt.log_key_name}  {receipt.log_public_key_b64}  (pin this out-of-band)")
    print(f"-> {result.summary()}")
    return 0 if result.ok else 1


def _selftest() -> int:
    """Seal a sample grant (anchored to a throwaway local TSA), verify it
    offline, then prove a one-byte tamper is caught. Proves the verification
    logic with zero network — the local TSA proves nothing about real time."""
    from datetime import UTC, datetime

    from tex.discovery.conduit.grant import DirectoryGrant
    from tex.discovery.conduit.seal import ConduitProvenanceChain, seal_grant
    from tex.domain.discovery import DiscoverySource
    from tex.interchange._local_tsa import LocalTSA, issue_timestamp_response, mint_local_tsa
    from tex.interchange.external_anchor import CheckpointAnchorRecord, anchor_subject_digest

    print("=" * 72)
    print("CONDUIT RECEIPT SELFTEST — seal a grant, verify offline, catch a tamper")
    print("=" * 72)

    tsa: LocalTSA = mint_local_tsa()

    def anchor(snapshot):
        cp = snapshot.checkpoint
        digest = anchor_subject_digest(cp.origin, cp.tree_size, cp.root_hash)
        resp = issue_timestamp_response(digest, tsa, nonce=4242)
        return CheckpointAnchorRecord.from_response(
            checkpoint=cp,
            signed_note=snapshot.signed_note,
            authority="local-demo-tsa",
            response_der=resp,
            request_nonce=4242,
        )

    chain = ConduitProvenanceChain(origin="tex.conduit/selftest")
    grant = DirectoryGrant(
        provider=DiscoverySource.OKTA,
        tenant_id="acme",
        requested_scopes=["okta.apps.read", "okta.clients.read", "okta.logs.read"],
        granted_scopes=["okta.apps.read", "okta.clients.read", "okta.logs.read"],
        consent_artifact_id="0oaSERVICEAPP123",
        consented_by="admin@acme.example",
        granted_at=datetime.now(UTC),
        credential_ref="vault://tex/okta/acme",
    )
    receipt = seal_grant(chain, grant, anchor=anchor)

    with tempfile.TemporaryDirectory() as td:
        rpath = Path(td) / "receipt.json"
        rpath.write_text(receipt.model_dump_json(), encoding="utf-8")
        reloaded = ConduitReceipt.model_validate_json(rpath.read_text(encoding="utf-8"))

    pin_key = chain.public_key_b64()
    good = reloaded.verify(pinned_log_public_key_b64=pin_key, pinned_tsa_cert_der=tsa.ca_pin_der)
    print(f"\n[genuine] {good.summary()}")

    # One-byte tamper: flip a granted scope inside the sealed payload.
    bad_payload = dict(reloaded.payload)
    bad_payload["granted_scopes"] = ["okta.apps.read", "okta.clients.read", "okta.logs.WRITE"]
    tampered = reloaded.model_copy(update={"payload": bad_payload})
    bad = tampered.verify(pinned_log_public_key_b64=pin_key, pinned_tsa_cert_der=tsa.ca_pin_der)
    print(f"[tampered] {bad.summary()}")

    held = good.ok and (not bad.ok)
    print("\n" + "=" * 72)
    print(f"RESULT: {'ALL CLAIMS HELD' if held else 'A CLAIM FAILED'} "
          f"(genuine verifies={good.ok}, tamper rejected={not bad.ok})")
    print("=" * 72)
    return 0 if held else 1


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Verify a tex-conduit receipt offline.")
    ap.add_argument("receipt", nargs="?", help="path to the receipt JSON")
    ap.add_argument("--pin", help="JSON pin file carrying log_public_key_b64")
    ap.add_argument("--tsa-cert", help="pinned TSA cert (DER) to verify the external anchor age")
    ap.add_argument("--selftest", action="store_true", help="seal+verify+tamper with no input file")
    args = ap.parse_args(argv)

    if args.selftest or not args.receipt:
        return _selftest()
    return _verify_file(args.receipt, args.pin, args.tsa_cert)


if __name__ == "__main__":
    raise SystemExit(main())
