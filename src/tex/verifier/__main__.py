"""
CLI: independently verify a sealed Tex verdict bundle, offline.

    python -m tex.verifier <bundle.json> --pin <public_key.pem>
    python -m tex.verifier <bundle.json> --pin tex.pem --pq-pin ml-dsa-65=pq.pem
    cat bundle.json | python -m tex.verifier - --pin tex.pem --json

Exit status is 0 iff the bundle is VALID (chain replays, signatures verify
against the pinned key, no invalid witness, no failed post-quantum signature,
and — with --require-witness — every decision is witnessed); 1 otherwise. This
process imports only ``tex.verifier.check`` (stdlib + cryptography); it never
loads the Tex decision engine.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from tex.verifier.check import verify_bundle


def _read(path: str) -> bytes:
    if path == "-":
        return sys.stdin.buffer.read()
    return Path(path).read_bytes()


def _parse_pq_pin(items: list[str]) -> dict[str, bytes]:
    pins: dict[str, bytes] = {}
    for item in items:
        if "=" not in item:
            raise SystemExit(f"--pq-pin expects ALGORITHM=path, got {item!r}")
        algo, path = item.split("=", 1)
        pins[algo.strip()] = Path(path).read_bytes()
    return pins


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m tex.verifier",
        description="Standalone offline verifier for sealed Tex verdict bundles.",
    )
    parser.add_argument("bundle", help="path to the bundle JSON ('-' for stdin)")
    parser.add_argument(
        "--pin", metavar="PEM",
        help="path to Tex's PINNED ECDSA public key (out-of-band). Without it "
             "the checker proves only internal consistency, not authorship.",
    )
    parser.add_argument(
        "--pq-pin", action="append", default=[], metavar="ALG=PEM",
        help="pinned PEM public key for a post-quantum signature algorithm "
             "(repeatable), e.g. ml-dsa-65=pq.pem",
    )
    parser.add_argument(
        "--require-witness", action="store_true",
        help="fail if any DECISION record lacks a monotonicity witness",
    )
    parser.add_argument("--json", action="store_true", help="emit the report as JSON")
    args = parser.parse_args(argv)

    try:
        raw = _read(args.bundle)
    except OSError as exc:
        print(f"error: cannot read bundle: {exc}", file=sys.stderr)
        return 2

    pinned = None
    if args.pin:
        try:
            pinned = Path(args.pin).read_bytes()
        except OSError as exc:
            print(f"error: cannot read pin: {exc}", file=sys.stderr)
            return 2

    report = verify_bundle(
        raw,
        pinned_public_key_pem=pinned,
        extra_pins=_parse_pq_pin(args.pq_pin),
        require_witness=args.require_witness,
    )

    if args.json:
        import json
        print(json.dumps(report.to_dict(), indent=2))
    else:
        print(report.summary())

    return 0 if report.is_valid else 1


if __name__ == "__main__":
    raise SystemExit(main())
