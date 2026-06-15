"""
The mechanical forge target — the single dare-agnostic entry the public dare
points at.

[Architecture: Layer 5 (Evidence) — proof-of-superiority tooling]

``CHALLENGE.md`` and ``scripts/verify_it_yourself.py --forge-target`` both route
through here. The doctrine this module enforces, and *only* this module:

    The pin is obtained OUT OF BAND — from a separate published statement file
    (``forge/PUBKEY_STATEMENT.json``), NEVER from the bundle.

That is the load-bearing defense. A verifier that read the public key from the
record it is checking would accept any self-consistent forgery: an attacker
re-signs a mutated payload with their own fresh key, embeds their own public
key, and the signature "checks out" against the key the attacker chose. The
whole point of the forge dare is that the relying party pins *Tex's* key — taken
from somewhere the attacker does not control — and rejects every record signed
by a different key. So ``load_published_pin`` reads the pin only from the
statement file and there is no convenience fallback to the bundle, ever.

This module bakes in NO headline / dare semantics. It is the foundation a future
frontier-lock framing (signed silence / sealed ABSTAIN / verifiable absence /
the SEAM) builds on. It only answers one question, the dare-agnostic one:
*does this bundle verify VALID against the published pin?*
"""

from __future__ import annotations

import base64
import hashlib
import json
import sys
from dataclasses import dataclass
from pathlib import Path

from tex.bench.evidence_bundle import BundleVerification, verify_bundle


@dataclass(frozen=True, slots=True)
class PublishedPin:
    """The out-of-band trust anchor, parsed from the statement file.

    ``public_key_b64`` is what the verifier pins. ``public_key_sha256`` is the
    fingerprint the founder ALSO posts in a second channel (live site / signed
    git tag / tweet); that externally-posted fingerprint — not this in-repo copy
    — is the canonical root of trust, because a hostile fork could swap both the
    in-repo bundle and the in-repo pin self-consistently. This module verifies
    the in-repo statement is internally consistent (fingerprint == hash of key)
    and surfaces the fingerprint so a human can cross-check it out of band.
    """

    algorithm: str
    key_id: str
    public_key_b64: str
    public_key_sha256: str
    attestor: str | None
    note: str | None

    @property
    def fingerprint_consistent(self) -> bool:
        """True iff public_key_sha256 == sha256(b64decode(public_key_b64))."""
        try:
            raw = base64.b64decode(self.public_key_b64, validate=True)
        except (ValueError, TypeError):
            return False
        return hashlib.sha256(raw).hexdigest() == self.public_key_sha256


def load_published_pin(pin_path: str | Path) -> PublishedPin:
    """Read the published pin from the SEPARATE statement file.

    Refuses, by construction, to read any key from a bundle: this function only
    takes a statement-file path and only returns the statement's own published
    key. The 'you got the key from the same repo as the bundle' criticism is
    answered by the second-channel fingerprint the statement carries — surfaced
    so a human cross-checks it, not silently trusted.

    Raises ``ValueError`` if the statement is missing required fields or its
    self-consistency check (fingerprint == hash of key) fails — a fail-closed
    refusal, not a silent acceptance.
    """
    path = Path(pin_path)
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError(f"pin statement {path} must be a JSON object")

    try:
        pin = PublishedPin(
            algorithm=raw["algorithm"],
            key_id=raw["key_id"],
            public_key_b64=raw["public_key_b64"],
            public_key_sha256=raw["public_key_sha256"],
            attestor=raw.get("attestor"),
            note=raw.get("note"),
        )
    except KeyError as exc:
        raise ValueError(
            f"pin statement {path} missing required field {exc.args[0]!r}"
        ) from exc

    if not pin.fingerprint_consistent:
        raise ValueError(
            f"pin statement {path} is internally inconsistent: public_key_sha256 "
            f"does not match sha256 of the decoded public_key_b64 — refusing to "
            f"trust a self-contradicting pin"
        )
    return pin


def verify_forge_target(
    bundle_path: str | Path, pin_path: str | Path
) -> BundleVerification:
    """Verify ``bundle_path`` against the pin published in ``pin_path``.

    The pin is read ONLY from the statement file (out of band relative to the
    bundle). Returns the full ``BundleVerification`` — ``.valid`` is the
    court-grade verdict: integrity + canonical bytes + authorship pinned to the
    published key.
    """
    pin = load_published_pin(pin_path)
    return verify_bundle(bundle_path, pinned_public_key_b64=pin.public_key_b64)


def _verdict_mix(bundle_path: str | Path) -> dict[str, int]:
    """Count the verdict types present in the bundle, for human reporting.

    Reads payloads with the duplicate-key-rejecting parse so the reported mix
    matches what the verifier acts on. ``decision`` rows are counted by their
    machine ``verdict`` (FORBID / PERMIT / ABSTAIN); ``human_resolution`` rows
    by ``human_verdict`` (e.g. ``refused``). Unparseable rows count as
    ``unparseable``.
    """
    from tex.bench.evidence_bundle import _reject_duplicate_keys, read_bundle

    mix: dict[str, int] = {}
    for record in read_bundle(bundle_path):
        try:
            payload = json.loads(
                record.payload_json, object_pairs_hook=_reject_duplicate_keys
            )
        except Exception:  # noqa: BLE001
            mix["unparseable"] = mix.get("unparseable", 0) + 1
            continue
        rtype = payload.get("record_type")
        if rtype == "human_resolution":
            key = f"human:{payload.get('human_verdict')}"
        elif rtype == "decision":
            key = str(payload.get("verdict"))
        else:
            key = str(rtype)
        mix[key] = mix.get(key, 0) + 1
    return mix


def _main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(
            "usage: python -m tex.bench.forge_target <bundle.jsonl> "
            "<PUBKEY_STATEMENT.json>",
            file=sys.stderr,
        )
        return 2
    bundle_path, pin_path = argv

    pin = load_published_pin(pin_path)
    result = verify_forge_target(bundle_path, pin_path)

    print("=" * 70)
    print("FORGE TARGET — offline verification against the OUT-OF-BAND pin")
    print("=" * 70)
    print(f"bundle : {bundle_path}")
    print(f"pin    : {pin_path}  (read out of band, NOT from the bundle)")
    print(f"pin algorithm   : {pin.algorithm}")
    print(f"pin key_id      : {pin.key_id}")
    print(f"pin fingerprint : sha256:{pin.public_key_sha256}")
    print(
        "  ^ cross-check this fingerprint against the founder's 2nd-channel "
        "post\n    (live site / signed git tag / tweet) — that external copy is "
        "the\n    canonical root of trust, not this in-repo statement file."
    )
    print()
    print(result.summary())
    print()
    print("verdict mix in bundle:")
    for key, count in sorted(_verdict_mix(bundle_path).items()):
        print(f"  {count:3}  {key}")
    print()
    print("=" * 70)
    print(f"FORGE TARGET: {'VALID' if result.valid else 'NOT VALID'}")
    print("=" * 70)
    return 0 if result.valid else 1


if __name__ == "__main__":
    raise SystemExit(_main(sys.argv[1:]))


__all__ = [
    "PublishedPin",
    "load_published_pin",
    "verify_forge_target",
]
