"""
CLI: ``python -m tex.verifier <bundle.json> --pubkey <key.pem>``.

Exit code is fail-closed: ``0`` only when the bundle fully verifies against the
pinned key; ``1`` when a check fails (or no key was pinned, so authorship is
unproven); ``2`` on a usage/IO error.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from tex.verifier.check import MLDSA_AVAILABLE, VerificationReport, load_bundle, verify_bundle


def _format_human(report: VerificationReport) -> str:
    def mark(ok: bool | None) -> str:
        return {True: "ok  ", False: "FAIL", None: "n/a "}[ok]

    lines = [
        f"sealed-bundle verification: {'VALID' if report.is_valid else 'INVALID'} "
        f"({report.record_count} record(s))",
        f"  [{mark(report.chain_intact)}] chain integrity"
        + (f" — break at {report.chain_break_at}" if not report.chain_intact else ""),
        f"  [{mark(report.signatures_valid)}] ECDSA signatures"
        + (
            f" — invalid at {report.signature_invalid_at}"
            if not report.signatures_valid
            else ""
        ),
        f"  [{mark(report.key_matches_pin if report.key_pinned else None)}] key pin"
        + (
            ""
            if report.key_pinned and report.key_matches_pin
            else " — UNPINNED: authorship NOT proven (pass --pubkey)"
            if not report.key_pinned
            else " — embedded key does NOT match the pinned key"
        ),
        f"  [{mark(report.pq_valid)}] ML-DSA co-signature"
        + (
            " — none present"
            if not report.pq_present
            else f" — invalid at {report.pq_invalid_at}"
            if report.pq_valid is False
            else " — present but no backend/pin to check"
            if report.pq_valid is None
            else ""
        ),
        f"  [{mark(report.witness_valid)}] monotonicity witness"
        + (
            " — none present (format pending)"
            if not report.witness_present
            else f" — {report.witness_checked} checked"
            if report.witness_valid
            else ""
        ),
    ]
    for fail in report.witness_failures:
        lines.append(f"        · {fail}")
    if not report.pq_present and report.require_pq:
        lines.append("  note: --require-pq set but no PQ co-signature in the bundle")
    if not report.witness_present and report.require_witness:
        lines.append("  note: --require-witness set but no witness in the bundle")
    if report.error:
        lines.append(f"  error: {report.error}")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m tex.verifier",
        description="Independently verify a sealed Tex verdict bundle "
        "(hash chain, signatures, monotonicity witness).",
    )
    parser.add_argument("bundle", help="path to the sealed bundle JSON")
    parser.add_argument(
        "--pubkey",
        help="path to the PINNED ECDSA public key (PEM). Without it, authorship "
        "cannot be proven and the result is INVALID by design.",
    )
    parser.add_argument(
        "--pq-pubkey",
        help="path to the pinned ML-DSA public key (PEM) for the dual "
        "post-quantum co-signature, if the bundle carries one.",
    )
    parser.add_argument(
        "--require-witness",
        action="store_true",
        help="fail if no monotonicity witness is present (forward-compatible "
        "fail-closed posture once the witness format is sealed).",
    )
    parser.add_argument(
        "--require-pq",
        action="store_true",
        help="fail unless a valid ML-DSA co-signature is present.",
    )
    parser.add_argument(
        "--json", action="store_true", help="emit the report as JSON instead of text"
    )
    args = parser.parse_args(argv)

    try:
        bundle = load_bundle(args.bundle)
    except (OSError, ValueError) as exc:
        print(f"error: cannot read bundle {args.bundle!r}: {exc}", file=sys.stderr)
        return 2

    pinned = None
    if args.pubkey:
        try:
            pinned = Path(args.pubkey).read_bytes()
        except OSError as exc:
            print(f"error: cannot read --pubkey {args.pubkey!r}: {exc}", file=sys.stderr)
            return 2

    pinned_pq = None
    if args.pq_pubkey:
        try:
            pinned_pq = Path(args.pq_pubkey).read_bytes()
        except OSError as exc:
            print(f"error: cannot read --pq-pubkey {args.pq_pubkey!r}: {exc}", file=sys.stderr)
            return 2
    if args.require_pq and not MLDSA_AVAILABLE:
        print(
            "warning: --require-pq set but this build has no native ML-DSA backend; "
            "PQ verification cannot succeed here.",
            file=sys.stderr,
        )

    report = verify_bundle(
        bundle,
        pinned_public_key_pem=pinned,
        pinned_pq_public_key_pem=pinned_pq,
        require_witness=args.require_witness,
        require_pq=args.require_pq,
    )

    if args.json:
        print(json.dumps(report.to_dict(), indent=2, sort_keys=True))
    else:
        print(_format_human(report))

    return 0 if report.is_valid else 1


if __name__ == "__main__":
    raise SystemExit(main())
