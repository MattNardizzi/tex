"""
Standalone offline verdict checker — the smallest trusted computing base.

Independently confirms a sealed Tex verdict bundle. This is "the verifier is
the pitch": the whole TCB is one file. It depends on **nothing** from the Tex
decision engine — no ``pdp.py``, recognizers, specialists, domain models, or
ledger — importing only the standard library plus ``cryptography`` (loaded
lazily, only to verify a signature). The canonical-JSON form, the SHA-256 hash
chain, and the monotonicity witness are all re-derived here from the sealed
bundle format alone; the claimed hashes are never trusted.

Three independent, fail-closed checks:

  1. **Hash-chain integrity.** Recompute ``payload_sha256`` from each record's
     own ``canonical_payload``, recompute ``record_hash`` from that plus the
     prior record's hash, and re-link the chain. Any reorder, deletion, or
     payload tamper — including a tampered witness, which lives *inside* the
     canonical payload — breaks replay.

  2. **Signature validity.** Verify each signature over the *recomputed*
     ``record_hash`` against a **pinned** key (Tex's known key, out-of-band —
     never the bundle's embedded key), so an attacker who re-signs with their
     own key fails the pin. ECDSA-P256 is live today; a second ML-DSA signature,
     if present, is verified too and fails closed (a checkable PQ signature that
     does not verify fails the bundle; one with no backend here is reported
     ``unverifiable``, never silently passed).

  3. **Monotonicity witness.** When a record seals a witness (ordered per-stage
     verdict transitions), check the invariant it asserts: no stage raised the
     verdict toward PERMIT, a fired structural floor forced FORBID, and only a
     structural (not probabilistic) stage fired the floor. The witness is read
     **only** from the signed ``canonical_payload`` — never an unsigned sidecar.

Honest limit: this proves the sealed witness is *internally consistent* with
the monotone-lowering / structural-floor invariants and is *tamper-evident and
Tex-authored*. It does NOT re-run the engine to prove the witness reflects the
real per-stage computation — that would require importing the engine, which is
exactly what this checker refuses to do. A witness that is internally valid but
lies about the run needs an engine replay (a different tool); what this catches
is a forged or invalid witness.

Maturity: ``production`` for the chain + ECDSA checks (re-derived from the live
``provenance/ledger.py`` format, byte-for-byte). The ML-DSA path is
``RUNTIME-DEPENDENT`` (verified only if a backend is installed). The witness
schema is ``research-early`` / ``UNVERIFIED-not-merged`` — the transcript+
witness format is being added by a sibling thread and is not on ``main`` yet,
so the schema here is the minimal one this checker assumes: a marked, tested
hook.
"""

from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass, field
from typing import Any

__all__ = [
    "PORTABLE_BUNDLE_VERSION",
    "SignatureResult",
    "RecordReport",
    "VerificationReport",
    "verify_bundle",
    "load_bundle",
    "check_monotonicity_witness",
]

# The schema version this checker understands. The producer-side bridge
# (``tex.verifier.export``) stamps the same string.
PORTABLE_BUNDLE_VERSION = "tex-offline-verdict/1"

# Verdicts ordered toward caution: PERMIT < ABSTAIN < FORBID. "Toward PERMIT"
# means a strictly smaller index; a monotone (non-raising) stage never lowers
# the index. This mirrors the runtime invariant in the engine's hold/gate
# (signals may only move a verdict toward caution), re-stated here so the
# checker needs no engine code to enforce it.
_VERDICT_CAUTION = {"PERMIT": 0, "ABSTAIN": 1, "FORBID": 2}

# Where a sealed monotonicity witness may live inside the canonical payload.
# Primary assumption: ``detail.monotonicity_witness`` (``detail`` is the
# free-form, already-sealed dict on every fact). A top-level
# ``monotonicity_witness`` is also honored in case the sibling thread seals it
# as a first-class canonical field. Both are inside ``canonical_payload`` →
# both are hash-covered and signature-bound.
_WITNESS_KEYS = ("monotonicity_witness", "witness")


# --------------------------------------------------------------------------- #
# canonical form — MUST match provenance/ledger.py byte-for-byte
# --------------------------------------------------------------------------- #
def _stable_json(obj: Any) -> str:
    """The ledger's exact canonical JSON. Re-implemented here (not imported) so
    the trusted computing base is this file. ``sort_keys`` makes key order
    irrelevant; ``separators`` strips whitespace; ``default=str`` is idempotent
    on the already-stringified canonical payload."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str)


def _sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _b64decode(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))


# --------------------------------------------------------------------------- #
# result shapes
# --------------------------------------------------------------------------- #
@dataclass(frozen=True, slots=True)
class SignatureResult:
    """One signature's outcome. ``verified`` is tri-state: ``True`` ok,
    ``False`` a real cryptographic failure (a backend checked it and it did not
    verify), ``None`` unverifiable on this machine (no backend for the
    algorithm) — reported honestly, never silently treated as valid."""

    algorithm: str
    verified: bool | None
    pinned: bool
    detail: str = ""


@dataclass(frozen=True, slots=True)
class RecordReport:
    index: int
    kind: str | None
    chain_ok: bool
    signatures: tuple[SignatureResult, ...]
    witness_present: bool
    witness_violations: tuple[str, ...]
    chain_detail: str = ""

    @property
    def primary_ok(self) -> bool:
        """The classical (ECDSA) signature path verified True."""
        ec = [s for s in self.signatures if s.algorithm == "ecdsa-p256"]
        return bool(ec) and all(s.verified is True for s in ec)


@dataclass(frozen=True, slots=True)
class VerificationReport:
    """The checker's verdict — every axis reported separately so a reader sees
    exactly what was and was not proven."""

    record_count: int
    chain_intact: bool
    chain_break_at: int | None
    signatures_valid: bool
    signature_invalid_at: int | None
    # None when no pin was supplied (the checker then proves only internal
    # consistency, not Tex authorship — surfaced loudly by the CLI).
    key_matches_pin: bool | None
    pinned: bool
    # Post-quantum second signature accounting.
    pq_present: bool
    pq_all_verified: bool
    pq_unverifiable: bool
    pq_invalid: bool
    # Monotonicity witness accounting.
    decisions_total: int
    decisions_witnessed: int
    witness_violations: tuple[tuple[int, tuple[str, ...]], ...]
    require_witness: bool
    records: tuple[RecordReport, ...] = field(default=(), repr=False)

    @property
    def is_valid(self) -> bool:
        """The baseline court-exhibit guarantee: the bundle has at least one
        record, the chain replays, every classical signature verifies against
        the pinned key, the pinned key was not contradicted, no sealed witness
        is invalid, no present-and-checkable PQ signature failed, and — if
        required — every decision is witnessed. An empty or unparseable bundle
        proves nothing and is never ``is_valid`` (fail-closed)."""
        return (
            self.record_count > 0
            and self.chain_intact
            and self.signatures_valid
            and self.key_matches_pin is not False
            and not self.pq_invalid
            and not self.witness_violations
            and (not self.require_witness
                 or self.decisions_witnessed == self.decisions_total)
        )

    @property
    def fully_verified(self) -> bool:
        """``is_valid`` AND every present PQ signature was actually verified
        (a backend existed and accepted it) — the strongest crypto posture."""
        return self.is_valid and not self.pq_unverifiable and (
            self.pq_all_verified if self.pq_present else True
        )

    @property
    def fully_witnessed(self) -> bool:
        """``is_valid`` AND every decision record carried a valid monotonicity
        witness — the strongest provenance posture."""
        return (
            self.is_valid
            and self.decisions_total > 0
            and self.decisions_witnessed == self.decisions_total
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "record_count": self.record_count,
            "chain_intact": self.chain_intact,
            "chain_break_at": self.chain_break_at,
            "signatures_valid": self.signatures_valid,
            "signature_invalid_at": self.signature_invalid_at,
            "key_matches_pin": self.key_matches_pin,
            "pinned": self.pinned,
            "pq_present": self.pq_present,
            "pq_all_verified": self.pq_all_verified,
            "pq_unverifiable": self.pq_unverifiable,
            "pq_invalid": self.pq_invalid,
            "decisions_total": self.decisions_total,
            "decisions_witnessed": self.decisions_witnessed,
            "witness_violations": [
                {"record": i, "violations": list(vs)}
                for i, vs in self.witness_violations
            ],
            "require_witness": self.require_witness,
            "is_valid": self.is_valid,
            "fully_verified": self.fully_verified,
            "fully_witnessed": self.fully_witnessed,
        }

    def summary(self) -> str:
        mark = "VALID" if self.is_valid else "INVALID"
        lines = [
            f"offline verdict bundle: {mark}  ({self.record_count} records)",
            f"  [{'ok ' if self.chain_intact else 'FAIL'}] chain integrity"
            + ("" if self.chain_intact else f" — break at {self.chain_break_at}"),
            f"  [{'ok ' if self.signatures_valid else 'FAIL'}] signatures (ECDSA)"
            + ("" if self.signatures_valid
               else f" — invalid at {self.signature_invalid_at}"),
        ]
        if not self.pinned:
            lines.append("  [warn] UNPINNED — proves internal consistency, "
                         "not Tex authorship; pass --pin <key.pem>")
        elif self.key_matches_pin is False:
            lines.append("  [FAIL] embedded key does NOT match the pin")
        elif self.signatures_valid:
            lines.append("  [ok ] authorship: signatures match the pinned key")
        else:
            lines.append("  [warn] embedded key matches the pin, but a signature "
                         "did not verify (see above) — authorship NOT proven")
        if self.pq_present:
            if self.pq_invalid:
                pq = "FAIL (a PQ signature did not verify)"
            elif self.pq_unverifiable:
                pq = "warn (present, no ML-DSA backend here — not checked)"
            else:
                pq = "ok (ML-DSA second signature verified)"
            lines.append(f"  [{'FAIL' if self.pq_invalid else 'ok '}] "
                         f"post-quantum: {pq}")
        wmark = "ok " if not self.witness_violations else "FAIL"
        lines.append(
            f"  [{wmark}] monotonicity witness: "
            f"{self.decisions_witnessed}/{self.decisions_total} decisions witnessed"
            + (f" — violations: {self.witness_violations}"
               if self.witness_violations else "")
        )
        if self.require_witness and self.decisions_witnessed != self.decisions_total:
            lines.append("  [FAIL] --require-witness: a decision has no witness")
        return "\n".join(lines)


# --------------------------------------------------------------------------- #
# signature verification — type-dispatched, cryptography loaded lazily
# --------------------------------------------------------------------------- #
def _verify_signature(message: bytes, signature_b64: str, pub_pem: bytes) -> bool | None:
    """Verify one signature over ``message`` against a PEM public key.

    Dispatches on the *loaded key type*, so it is robust to a mislabeled
    algorithm tag: an EC key uses ECDSA-P256+SHA-256; an ML-DSA key uses
    FIPS-204 pure verify. Returns ``True``/``False`` for a real outcome, or
    ``None`` when no backend can interpret the key (e.g. ML-DSA on
    cryptography < 48) — never guesses."""
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
    except Exception:  # pragma: no cover - cryptography is a hard dep of verify
        return None
    try:
        sig = _b64decode(signature_b64)
        pub = serialization.load_pem_public_key(pub_pem)
    except Exception:  # noqa: BLE001 - tampered/garbage input must not raise
        return False

    if isinstance(pub, ec.EllipticCurvePublicKey):
        try:
            pub.verify(sig, message, ec.ECDSA(hashes.SHA256()))
            return True
        except InvalidSignature:
            return False
        except Exception:  # noqa: BLE001
            return False

    # ML-DSA (FIPS 204) — only on cryptography >= 48; import guarded so the
    # classical path works without it.
    try:
        from cryptography.hazmat.primitives.asymmetric import mldsa
        mldsa_pub = (
            mldsa.MLDSA44PublicKey,
            mldsa.MLDSA65PublicKey,
            mldsa.MLDSA87PublicKey,
        )
    except Exception:  # noqa: BLE001
        mldsa_pub = ()
    if mldsa_pub and isinstance(pub, mldsa_pub):
        try:
            pub.verify(sig, message)
            return True
        except InvalidSignature:
            return False
        except Exception:  # noqa: BLE001
            return False

    # Unknown key type — cannot verify here, do not pretend to.
    return None


# --------------------------------------------------------------------------- #
# monotonicity witness
# --------------------------------------------------------------------------- #
def check_monotonicity_witness(witness: Any) -> list[str]:
    """Return a list of violation codes for a sealed monotonicity witness.

    Empty list ⇒ the witness is internally valid against the invariants:
      * every stage is monotone (caution never decreases — no raise toward
        PERMIT);
      * the per-stage chain is continuous (each stage starts where the last
        ended), and the final verdict equals the last stage's output;
      * a fired structural floor forces the final verdict to FORBID and is
        carried by a *structural* stage, never a probabilistic one (a high
        probabilistic score must not fire the floor);
      * the ``structural_floor_fired`` flag matches what the stages show.

    Fail-closed: any malformed shape is a violation, never an exception. See
    the module docstring for the honest limit (internal consistency, not a
    re-run of the engine)."""
    v: list[str] = []
    if not isinstance(witness, dict):
        return ["witness_not_object"]

    def caution(verdict: Any) -> int | None:
        return _VERDICT_CAUTION.get(verdict) if isinstance(verdict, str) else None

    base = witness.get("base_verdict", "PERMIT")
    if caution(base) is None:
        v.append(f"unknown_verdict:base={base!r}")
        base = None

    final = witness.get("final_verdict")
    if caution(final) is None:
        v.append(f"unknown_verdict:final={final!r}")

    stages = witness.get("stages")
    if not isinstance(stages, list):
        v.append("stages_not_list")
        stages = []

    declared_floor = bool(witness.get("structural_floor_fired", False))
    any_floor = False
    prev_out = base

    for i, st in enumerate(stages):
        if not isinstance(st, dict):
            v.append(f"stage_not_object@{i}")
            continue
        v_in = st.get("verdict_in")
        v_out = st.get("verdict_out")
        c_in, c_out = caution(v_in), caution(v_out)
        if c_in is None or c_out is None:
            v.append(f"unknown_verdict@{i}")
        else:
            if prev_out is not None and v_in != prev_out:
                v.append(f"broken_stage_chain@{i}")
            if c_out < c_in:  # caution decreased ⇒ raised toward PERMIT
                v.append(f"raised_toward_permit@{i}")
        if bool(st.get("structural_floor", False)):
            any_floor = True
            if st.get("kind") == "probabilistic":
                v.append(f"probabilistic_fired_floor@{i}")
            if v_out != "FORBID":
                v.append(f"floor_stage_not_forbid@{i}")
        prev_out = v_out if caution(v_out) is not None else prev_out

    # continuity into the final verdict
    if stages and prev_out is not None and final is not None and final != prev_out:
        v.append("final_not_last_stage")
    if not stages and base is not None and final is not None and final != base:
        v.append("final_not_base_without_stages")

    # the declared flag must reflect reality, and a fired floor ⇒ FORBID
    if declared_floor != any_floor:
        v.append("floor_flag_inconsistent")
    if (declared_floor or any_floor) and final != "FORBID":
        v.append("floor_fired_without_forbid")
    return v


def _extract_witness(canonical_payload: dict[str, Any]) -> Any | None:
    """Pull the witness from the signed canonical payload (never a sidecar)."""
    detail = canonical_payload.get("detail")
    if isinstance(detail, dict):
        for k in _WITNESS_KEYS:
            if detail.get(k) is not None:
                return detail[k]
    for k in _WITNESS_KEYS:
        if canonical_payload.get(k) is not None:
            return canonical_payload[k]
    return None


# --------------------------------------------------------------------------- #
# the verifier
# --------------------------------------------------------------------------- #
def load_bundle(source: str | bytes | dict[str, Any]) -> dict[str, Any]:
    """Parse a portable bundle from a dict, JSON string, or JSON bytes."""
    if isinstance(source, dict):
        return source
    if isinstance(source, bytes):
        source = source.decode("utf-8")
    return json.loads(source)


def _resolve_key(
    sig: dict[str, Any],
    algorithm: str,
    keys: dict[str, str],
    bundle_pub_b64: str | None,
) -> bytes | None:
    """The key the bundle *declares* for a signature: the signature's own
    embedded key, else the bundle-level key map, else the legacy single key
    (ECDSA only)."""
    b64 = sig.get("public_key_b64") or keys.get(algorithm)
    if b64 is None and algorithm == "ecdsa-p256":
        b64 = bundle_pub_b64
    if b64 is None:
        return None
    try:
        return _b64decode(b64)
    except Exception:  # noqa: BLE001
        return None


def verify_bundle(
    source: str | bytes | dict[str, Any],
    *,
    pinned_public_key_pem: bytes | None = None,
    extra_pins: dict[str, bytes] | None = None,
    require_witness: bool = False,
) -> VerificationReport:
    """Verify a portable verdict bundle from scratch.

    Holds only the bundle, an optional **pinned** ECDSA public key (Tex's known
    key, out-of-band), and optional per-algorithm extra pins for PQ signatures.
    Standalone: no ledger, database, network, or Tex runtime. Never raises on
    tampered input — every failure is a field on the returned report."""
    extra_pins = extra_pins or {}
    try:
        bundle = load_bundle(source)
    except Exception:  # noqa: BLE001 - unparseable bundle is a hard fail
        return VerificationReport(
            record_count=0, chain_intact=False, chain_break_at=0,
            signatures_valid=False, signature_invalid_at=0,
            key_matches_pin=None, pinned=pinned_public_key_pem is not None,
            pq_present=False, pq_all_verified=False, pq_unverifiable=False,
            pq_invalid=False, decisions_total=0, decisions_witnessed=0,
            witness_violations=(), require_witness=require_witness, records=(),
        )

    raw_records = bundle.get("records") or []
    keys = bundle.get("keys") or {}
    bundle_pub_b64 = bundle.get("public_key_b64")

    pinned = pinned_public_key_pem is not None
    key_matches_pin: bool | None = None
    if pinned:
        declared_ec = keys.get("ecdsa-p256") or bundle_pub_b64
        try:
            key_matches_pin = bool(declared_ec) and (
                _b64decode(declared_ec) == pinned_public_key_pem
            )
        except Exception:  # noqa: BLE001
            key_matches_pin = False

    chain_intact = True
    chain_break_at: int | None = None
    signatures_valid = True
    signature_invalid_at: int | None = None
    pq_present = pq_invalid = pq_unverifiable = False
    pq_all_verified = True
    decisions_total = decisions_witnessed = 0
    witness_violations: list[tuple[int, tuple[str, ...]]] = []
    record_reports: list[RecordReport] = []

    previous_hash: str | None = None
    chain_live = True  # once the chain breaks, later records can't be trusted

    for idx, rec in enumerate(raw_records):
        cp = rec.get("canonical_payload")
        kind = cp.get("kind") if isinstance(cp, dict) else None

        # 1) chain replay — recompute, never trust the claimed hashes
        rec_chain_ok = False
        chain_detail = ""
        record_hash = None
        if chain_live and isinstance(cp, dict):
            payload_sha256 = _sha256_hex(_stable_json(cp))
            record_hash = _sha256_hex(
                _stable_json(
                    {"payload_sha256": payload_sha256, "previous_hash": previous_hash}
                )
            )
            rec_chain_ok = (
                rec.get("previous_hash") == previous_hash
                and rec.get("payload_sha256") == payload_sha256
                and rec.get("record_hash") == record_hash
            )
            if not rec_chain_ok:
                chain_detail = "recomputed hash/link mismatch"
        elif not isinstance(cp, dict):
            chain_detail = "missing canonical_payload"

        if not rec_chain_ok and chain_intact:
            chain_intact = False
            chain_break_at = idx
        if not rec_chain_ok:
            chain_live = False

        # 2) signatures — verify over the RECOMPUTED record_hash against the pin
        sig_results: list[SignatureResult] = []
        sigs = _normalize_signatures(rec, bundle_pub_b64)
        message = record_hash.encode("ascii") if record_hash is not None else b""
        for sig in sigs:
            algo = str(sig.get("algorithm", "ecdsa-p256"))
            is_pq = algo != "ecdsa-p256"
            pin = extra_pins.get(algo) if is_pq else pinned_public_key_pem
            use_pin = pin is not None
            verify_key = pin if use_pin else _resolve_key(
                sig, algo, keys, bundle_pub_b64
            )
            if not rec_chain_ok or verify_key is None:
                verified: bool | None = None if verify_key is None else False
                detail = "no key" if verify_key is None else "chain broken"
            else:
                verified = _verify_signature(
                    message, str(sig.get("signature_b64", "")), verify_key
                )
                detail = "" if verified else "signature did not verify"
            sig_results.append(
                SignatureResult(algorithm=algo, verified=verified,
                                pinned=use_pin, detail=detail)
            )
            if is_pq:
                pq_present = True
                if verified is True:
                    pass
                elif verified is False:
                    pq_invalid = True
                    pq_all_verified = False
                else:
                    pq_unverifiable = True
                    pq_all_verified = False

        # classical signature governs signatures_valid
        ec_sigs = [s for s in sig_results if s.algorithm == "ecdsa-p256"]
        primary_ok = bool(ec_sigs) and all(s.verified is True for s in ec_sigs)
        if not primary_ok and signatures_valid:
            signatures_valid = False
            signature_invalid_at = idx

        # 3) monotonicity witness (from the signed canonical payload only)
        witness = _extract_witness(cp) if isinstance(cp, dict) else None
        w_present = witness is not None
        w_viol: tuple[str, ...] = ()
        if kind == "decision":
            decisions_total += 1
        if w_present:
            w_viol = tuple(check_monotonicity_witness(witness))
            if w_viol:
                witness_violations.append((idx, w_viol))
            elif kind == "decision":
                decisions_witnessed += 1
        elif require_witness and kind == "decision":
            w_viol = ("missing_witness",)
            witness_violations.append((idx, w_viol))

        record_reports.append(
            RecordReport(
                index=idx, kind=kind, chain_ok=rec_chain_ok,
                signatures=tuple(sig_results), witness_present=w_present,
                witness_violations=w_viol, chain_detail=chain_detail,
            )
        )
        if rec_chain_ok:
            previous_hash = record_hash

    return VerificationReport(
        record_count=len(raw_records),
        chain_intact=chain_intact,
        chain_break_at=chain_break_at,
        signatures_valid=signatures_valid,
        signature_invalid_at=signature_invalid_at,
        key_matches_pin=key_matches_pin,
        pinned=pinned,
        pq_present=pq_present,
        pq_all_verified=pq_all_verified and pq_present,
        pq_unverifiable=pq_unverifiable,
        pq_invalid=pq_invalid,
        decisions_total=decisions_total,
        decisions_witnessed=decisions_witnessed,
        witness_violations=tuple(witness_violations),
        require_witness=require_witness,
        records=tuple(record_reports),
    )


def _normalize_signatures(
    rec: dict[str, Any], bundle_pub_b64: str | None
) -> list[dict[str, Any]]:
    """Accept both the multi-signature form (``signatures: [...]``) and the
    legacy single-ECDSA form (``signature_b64`` on the record), so a bundle
    minted straight from ``main``'s ledger and a future dual-signed bundle both
    verify through one path."""
    sigs = rec.get("signatures")
    if isinstance(sigs, list) and sigs:
        return [s for s in sigs if isinstance(s, dict)]
    if rec.get("signature_b64"):
        return [{
            "algorithm": "ecdsa-p256",
            "signature_b64": rec["signature_b64"],
            "public_key_b64": rec.get("public_key_b64") or bundle_pub_b64,
        }]
    return []
