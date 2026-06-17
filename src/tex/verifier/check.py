"""
Standalone sealed-verdict-bundle verifier — the verifier *is* the pitch.

Given a sealed verdict bundle (the JSON ``provenance/bundle.py`` exports), this
module independently confirms three things:

  1. **Chain integrity** — replays the SHA-256 hash chain from the records'
     own bytes. Any reordering, deletion, or content tamper breaks replay.
  2. **Authorship** — verifies every record's ECDSA-P256 signature against a
     **pinned** public key (and an optional ML-DSA-65 co-signature, the dual
     post-quantum half, when present). A self-describing signature only proves
     *Tex* authored a record if it is checked against *Tex's known key* — so the
     pin is load-bearing and the key the bundle carries is never the basis of
     trust.
  3. **Monotonicity witness** — for each sealed DECISION that carries a verdict
     transcript, confirms the governance invariant: no stage raised the verdict
     toward PERMIT (monotone lowering), a fired structural floor forced FORBID,
     and the witness's final verdict matches the verdict actually sealed.

THE TRUSTED COMPUTING BASE IS DELIBERATELY TINY. This module imports **only the
Python standard library and ``cryptography``** — no Tex decision engine, no
recognizers, no specialists, and (on purpose) not even Tex's own ledger, bundle,
or domain models. It re-derives every sealed byte from the documented wire
format, so an adversary auditing the claim reads exactly one file plus two
well-known dependencies, and a serialization bug in the *producer* would surface
here as a mismatch rather than be reproduced by shared code. ``tex.provenance``
is intentionally NOT imported: importing it would transitively pull in the
producer ledger (its package ``__init__`` is eager), enlarging the very TCB this
verifier exists to keep small.

Honesty / scope (re-verify if the crypto or bundle format changes):
  * The live signer is ECDSA-P256; the chain proves integrity, a signature
    proves authorship of one record. ML-DSA-65 is verified only when the bundle
    actually carries a PQ co-signature AND the installed ``cryptography`` exposes
    a native ML-DSA backend (``cryptography>=49`` here) — otherwise the PQ result
    is ``None`` (RUNTIME-DEPENDENT), reported honestly, fail-closed under
    ``require_pq``. Neither half is a post-quantum guarantee unless the bundle
    was produced with, and pinned to, a PQ key.
  * The monotonicity-witness schema below is the verifier-side *expected* format
    pending the companion session that seals it into each DECISION's ``detail``.
    When no record carries a witness, that check is reported absent (not passed);
    when one is present it MUST verify or the bundle FAILS. ``require_witness``
    turns absence into a failure for callers that mandate it.
  * Composition (e-value) replay is intentionally OUT OF SCOPE — it needs the
    e-value combiners and so a larger TCB. Use ``tex.provenance.bundle`` for that
    stronger, producer-coupled check. This verifier's mandate is chain +
    authorship + witness.
"""

from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

# ML-DSA (FIPS 204) landed in pyca/cryptography as native classes. Probe for it
# so the dual-signature hook degrades honestly on an older build instead of
# importing-failing the whole verifier.
try:  # pragma: no cover - exercised by whichever branch the install lands on
    from cryptography.hazmat.primitives.asymmetric import mldsa as _mldsa

    _MLDSA_PUBLIC_TYPES: tuple[type, ...] = (
        _mldsa.MLDSA44PublicKey,
        _mldsa.MLDSA65PublicKey,
        _mldsa.MLDSA87PublicKey,
    )
    MLDSA_AVAILABLE = True
except Exception:  # noqa: BLE001 - any import failure means no PQ backend
    _mldsa = None  # type: ignore[assignment]
    _MLDSA_PUBLIC_TYPES = ()
    MLDSA_AVAILABLE = False


__all__ = [
    "VerificationReport",
    "verify_bundle",
    "load_bundle",
    "MLDSA_AVAILABLE",
    "WITNESS_KEY",
]

# The location, inside a DECISION fact's ``detail``, where the companion session
# seals the verdict transcript + monotonicity witness. Defined here as the
# expected contract so the hook is concrete and testable before the seal lands.
WITNESS_KEY = "monotonicity_witness"

# Caution ordering: a probabilistic signal may only move a verdict toward
# caution (PERMIT -> ABSTAIN -> FORBID), never the reverse. Higher rank == more
# caution. "Raising toward PERMIT" is any step that lowers the rank.
_VERDICT_RANK: dict[str, int] = {"PERMIT": 0, "ABSTAIN": 1, "FORBID": 2}

# The PQ co-signature fields a future producer is expected to add to each record
# (the existing ``SealedFactRecord`` is ``extra="forbid"``, so the dual signature
# arrives as new sibling keys, read here from the raw wire JSON).
_PQ_SIG_KEY = "pq_signature_b64"


# --------------------------------------------------------------------------- #
# canonical form — the sealed bundle FORMAT, re-implemented (never imported)
# --------------------------------------------------------------------------- #
def _stable_json(obj: Any) -> str:
    """The ledger's exact canonical serialization (``provenance/ledger.py``):
    sorted keys, tight separators, ``str`` fallback. Must match byte-for-byte or
    a recomputed hash will not line up with the seal."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str)


def _sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _norm_dt(value: Any) -> Any:
    """Normalize an ISO-8601 timestamp string to Python's ``datetime.isoformat``
    form, the form the producer sealed. The bundle JSON carries pydantic's
    serialization (a trailing ``Z`` for UTC); the seal was computed over
    ``datetime.isoformat()`` (``+00:00``). Round-tripping through
    ``fromisoformat().isoformat()`` reconciles them without trusting either
    library. Non-strings pass through so a malformed bundle fails the hash
    check, not here."""
    if not isinstance(value, str):
        return value
    try:
        return datetime.fromisoformat(value).isoformat()
    except ValueError:
        return value


def _evidence_canonical(ev: dict[str, Any] | None) -> dict[str, Any] | None:
    """Reconstruct ``CombinedEvidence.canonical_payload`` from raw JSON."""
    if ev is None:
        return None
    return {
        "combination_id": ev.get("combination_id"),
        "decision_id": ev.get("decision_id"),
        "combiner": ev.get("combiner"),
        "log_e_value": ev.get("log_e_value"),
        "is_true_e_value": ev.get("is_true_e_value"),
        "anytime_valid": ev.get("anytime_valid"),
        "joint_null_hypothesis_id": ev.get("joint_null_hypothesis_id"),
        "filtration_id": ev.get("filtration_id"),
        "maturity": ev.get("maturity"),
        "component_ids": list(ev.get("component_ids", [])),
        "excluded_ids": list(ev.get("excluded_ids", [])),
        "n_components": ev.get("n_components"),
        "justification": ev.get("justification"),
        "recorded_at": _norm_dt(ev.get("recorded_at")),
    }


def _fact_canonical(fact: dict[str, Any]) -> dict[str, Any]:
    """Reconstruct ``SealedFact.canonical_payload`` from raw JSON — the exact
    dict the ledger hashed into ``payload_sha256``."""
    return {
        "fact_id": fact.get("fact_id"),
        "kind": fact.get("kind"),
        "subject_id": fact.get("subject_id"),
        "claim": fact.get("claim"),
        "evidence": _evidence_canonical(fact.get("evidence")),
        "maturity": fact.get("maturity"),
        "detail": fact.get("detail", {}),
        "created_at": _norm_dt(fact.get("created_at")),
    }


# --------------------------------------------------------------------------- #
# signature primitives — crypto only
# --------------------------------------------------------------------------- #
def _verify_ecdsa(public_key_pem: bytes, message: bytes, signature: bytes) -> bool:
    """Verify an ECDSA-P256 + SHA-256 signature. Mirrors the producer's
    ``EcdsaP256Provider.verify`` using ``cryptography`` directly."""
    try:
        pub = serialization.load_pem_public_key(public_key_pem)
    except (ValueError, TypeError):
        return False
    if not isinstance(pub, ec.EllipticCurvePublicKey):
        return False
    try:
        pub.verify(signature, message, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature:
        return False
    return True


def _verify_mldsa(public_key_pem: bytes, message: bytes, signature: bytes) -> bool | None:
    """Verify an ML-DSA (FIPS 204) co-signature. Returns ``None`` when no native
    backend is available (RUNTIME-DEPENDENT — the honest "couldn't check"), and
    ``False`` for a bad key or a failed verification (fail-closed)."""
    if not MLDSA_AVAILABLE:
        return None
    try:
        pub = serialization.load_pem_public_key(public_key_pem)
    except (ValueError, TypeError):
        return False
    if not isinstance(pub, _MLDSA_PUBLIC_TYPES):
        return False
    try:
        pub.verify(signature, message)
    except InvalidSignature:
        return False
    return True


def _b64_or_none(value: Any) -> bytes | None:
    if not isinstance(value, str):
        return None
    try:
        return base64.b64decode(value.encode("ascii"))
    except Exception:  # noqa: BLE001
        return None


# --------------------------------------------------------------------------- #
# report
# --------------------------------------------------------------------------- #
@dataclass(frozen=True, slots=True)
class VerificationReport:
    """Every check reported separately, so a reader sees exactly what was and
    was not proven. ``is_valid`` is fail-closed: any error, an unintact chain, a
    bad signature, an unpinned key, a present-but-failing witness or PQ
    co-signature all force it False."""

    record_count: int
    # chain
    chain_intact: bool
    chain_break_at: int | None
    # ECDSA authorship (verified against the PIN, never the embedded key)
    signatures_valid: bool
    signature_invalid_at: int | None
    key_pinned: bool
    key_matches_pin: bool
    # dual post-quantum co-signature (optional, fail-closed)
    pq_present: bool
    pq_backend_available: bool
    pq_valid: bool | None
    pq_invalid_at: int | None
    # monotonicity witness
    witness_present: bool
    witness_checked: int
    witness_valid: bool | None
    witness_failures: tuple[str, ...]
    # policy knobs the caller set
    require_witness: bool
    require_pq: bool
    # set iff the bundle could not even be parsed — fail closed
    error: str | None = None

    @property
    def internally_consistent(self) -> bool:
        """Chain replays and every signature verifies against whatever key was
        used. Honest for the no-pin case: consistent, but authorship UNPROVEN
        until a pin is supplied."""
        return self.error is None and self.chain_intact and self.signatures_valid

    @property
    def is_valid(self) -> bool:
        if self.error is not None:
            return False
        ok = (
            self.chain_intact
            and self.signatures_valid
            and self.key_pinned
            and self.key_matches_pin
            and self.pq_valid is not False
            and self.witness_valid is not False
        )
        if self.require_pq:
            ok = ok and self.pq_valid is True
        if self.require_witness:
            ok = ok and self.witness_valid is True
        return ok

    def to_dict(self) -> dict[str, Any]:
        return {
            "is_valid": self.is_valid,
            "internally_consistent": self.internally_consistent,
            "record_count": self.record_count,
            "chain_intact": self.chain_intact,
            "chain_break_at": self.chain_break_at,
            "signatures_valid": self.signatures_valid,
            "signature_invalid_at": self.signature_invalid_at,
            "key_pinned": self.key_pinned,
            "key_matches_pin": self.key_matches_pin,
            "pq_present": self.pq_present,
            "pq_backend_available": self.pq_backend_available,
            "pq_valid": self.pq_valid,
            "pq_invalid_at": self.pq_invalid_at,
            "witness_present": self.witness_present,
            "witness_checked": self.witness_checked,
            "witness_valid": self.witness_valid,
            "witness_failures": list(self.witness_failures),
            "require_witness": self.require_witness,
            "require_pq": self.require_pq,
            "error": self.error,
        }


# --------------------------------------------------------------------------- #
# monotonicity witness
# --------------------------------------------------------------------------- #
def _check_witness(detail: dict[str, Any], idx: int) -> list[str]:
    """Check the monotonicity witness in one DECISION's ``detail``. Returns a
    list of human-readable failures (empty == the witness holds).

    Invariants (all fail-closed):
      * stages form a continuous chain of verdict transitions;
      * no stage raises the verdict toward PERMIT (rank never decreases) and no
        stage carries a negative caution ``score_delta``;
      * if the structural floor fired, the final verdict is FORBID;
      * the witness's final verdict equals the verdict actually sealed in
        ``detail['verdict']`` (so a benign transcript cannot be forged over a
        FORBID seal, or vice versa).
    """
    w = detail.get(WITNESS_KEY)
    fails: list[str] = []
    if not isinstance(w, dict):
        return [f"record {idx}: witness is not an object"]
    stages = w.get("stages")
    if not isinstance(stages, list) or not stages:
        fails.append(f"record {idx}: witness has no stages")
        stages = []

    prev_after: str | None = None
    for j, st in enumerate(stages):
        if not isinstance(st, dict):
            fails.append(f"record {idx} stage {j}: not an object")
            continue
        vb, va = st.get("verdict_before"), st.get("verdict_after")
        if vb not in _VERDICT_RANK or va not in _VERDICT_RANK:
            fails.append(f"record {idx} stage {j}: unknown verdict {vb!r}->{va!r}")
            continue
        if prev_after is not None and vb != prev_after:
            fails.append(
                f"record {idx} stage {j}: discontinuous ({prev_after}->{vb})"
            )
        if _VERDICT_RANK[va] < _VERDICT_RANK[vb]:
            fails.append(
                f"record {idx} stage {j}: raised toward PERMIT ({vb}->{va})"
            )
        delta = st.get("score_delta")
        if isinstance(delta, (int, float)) and not isinstance(delta, bool) and delta < 0:
            fails.append(f"record {idx} stage {j}: negative score_delta {delta}")
        prev_after = va

    final = w.get("final_verdict")
    if final not in _VERDICT_RANK:
        fails.append(f"record {idx}: unknown final_verdict {final!r}")
    if prev_after is not None and final is not None and final != prev_after:
        fails.append(
            f"record {idx}: final_verdict {final!r} != last stage {prev_after!r}"
        )
    if bool(w.get("structural_floor_fired")) and final != "FORBID":
        fails.append(
            f"record {idx}: structural floor fired but final_verdict={final!r}"
        )
    sealed = detail.get("verdict")
    if sealed is not None and final is not None and sealed != final:
        fails.append(
            f"record {idx}: witness final {final!r} != sealed verdict {sealed!r}"
        )
    return fails


# --------------------------------------------------------------------------- #
# the verifier
# --------------------------------------------------------------------------- #
def verify_bundle(
    bundle: dict[str, Any] | str,
    *,
    pinned_public_key_pem: bytes | None,
    pinned_pq_public_key_pem: bytes | None = None,
    require_witness: bool = False,
    require_pq: bool = False,
) -> VerificationReport:
    """Verify a sealed verdict bundle from scratch.

    ``bundle`` is the parsed JSON object (or its JSON string). Authorship is only
    counted against ``pinned_public_key_pem`` — pass ``None`` only to inspect
    internal consistency (``is_valid`` is then False because authorship is
    unproven). Never raises on hostile input: a parse failure becomes a fail-
    closed report with ``error`` set.
    """
    if isinstance(bundle, str):
        try:
            bundle = json.loads(bundle)
        except (ValueError, TypeError) as exc:
            return _error_report(f"bundle is not valid JSON: {exc}", require_witness, require_pq)
    if not isinstance(bundle, dict):
        return _error_report("bundle is not a JSON object", require_witness, require_pq)

    records = bundle.get("records")
    if not isinstance(records, list):
        return _error_report("bundle has no records array", require_witness, require_pq)

    embedded_key = _b64_or_none(bundle.get("public_key_b64"))
    key_pinned = pinned_public_key_pem is not None
    key_matches_pin = key_pinned and embedded_key == pinned_public_key_pem
    # The key signatures are checked against: the PIN when supplied, else the
    # embedded key (best-effort internal consistency, loudly unpinned).
    verify_key = pinned_public_key_pem if key_pinned else embedded_key

    chain_intact = True
    chain_break_at: int | None = None
    signatures_valid = True
    signature_invalid_at: int | None = None
    pq_present = False
    pq_valid: bool | None = None
    pq_invalid_at: int | None = None
    witness_present = False
    witness_checked = 0
    witness_valid: bool | None = None
    witness_failures: list[str] = []

    previous_hash: str | None = None
    for idx, rec in enumerate(records):
        if not isinstance(rec, dict) or not isinstance(rec.get("fact"), dict):
            chain_intact = False
            chain_break_at = idx
            break

        # 1) chain replay — recompute payload + record hash, never trust claims
        payload_sha256 = _sha256_hex(_stable_json(_fact_canonical(rec["fact"])))
        record_hash = _sha256_hex(
            _stable_json({"payload_sha256": payload_sha256, "previous_hash": previous_hash})
        )
        if (
            rec.get("previous_hash") != previous_hash
            or rec.get("payload_sha256") != payload_sha256
            or rec.get("record_hash") != record_hash
        ):
            chain_intact = False
            chain_break_at = idx
            break

        message = record_hash.encode("ascii")

        # 2a) ECDSA authorship over the RECOMPUTED hash, against the chosen key
        sig = _b64_or_none(rec.get("signature_b64"))
        ok = verify_key is not None and sig is not None and _verify_ecdsa(
            verify_key, message, sig
        )
        if not ok and signatures_valid:
            signatures_valid = False
            signature_invalid_at = idx

        # 2b) dual ML-DSA co-signature (optional, fail-closed)
        pq_sig = _b64_or_none(rec.get(_PQ_SIG_KEY))
        if pq_sig is not None:
            pq_present = True
            result: bool | None = None
            if pinned_pq_public_key_pem is not None:
                result = _verify_mldsa(pinned_pq_public_key_pem, message, pq_sig)
            # No PQ pin => cannot attribute the co-signature; leave it unchecked.
            if result is False and pq_valid is not False:
                pq_valid = False
                pq_invalid_at = idx
            elif result is True and pq_valid is None:
                pq_valid = True

        # 3) monotonicity witness, when this record carries one
        detail = rec["fact"].get("detail")
        if isinstance(detail, dict) and WITNESS_KEY in detail:
            witness_present = True
            witness_checked += 1
            fails = _check_witness(detail, idx)
            if fails:
                witness_failures.extend(fails)

        previous_hash = rec.get("record_hash")

    if witness_present:
        witness_valid = not witness_failures

    return VerificationReport(
        record_count=len(records),
        chain_intact=chain_intact,
        chain_break_at=chain_break_at,
        signatures_valid=signatures_valid,
        signature_invalid_at=signature_invalid_at,
        key_pinned=key_pinned,
        key_matches_pin=key_matches_pin,
        pq_present=pq_present,
        pq_backend_available=MLDSA_AVAILABLE,
        pq_valid=pq_valid,
        pq_invalid_at=pq_invalid_at,
        witness_present=witness_present,
        witness_checked=witness_checked,
        witness_valid=witness_valid,
        witness_failures=tuple(witness_failures),
        require_witness=require_witness,
        require_pq=require_pq,
    )


def _error_report(msg: str, require_witness: bool, require_pq: bool) -> VerificationReport:
    return VerificationReport(
        record_count=0,
        chain_intact=False,
        chain_break_at=None,
        signatures_valid=False,
        signature_invalid_at=None,
        key_pinned=False,
        key_matches_pin=False,
        pq_present=False,
        pq_backend_available=MLDSA_AVAILABLE,
        pq_valid=None,
        pq_invalid_at=None,
        witness_present=False,
        witness_checked=0,
        witness_valid=None,
        witness_failures=(),
        require_witness=require_witness,
        require_pq=require_pq,
        error=msg,
    )


def load_bundle(path: str | Path) -> dict[str, Any]:
    """Read a bundle JSON file into a plain dict (the verifier's input)."""
    return json.loads(Path(path).read_text(encoding="utf-8"))
