"""
Proof-of-possession (PoP) for Tex authority credentials — RFC 7800 / RFC 9449
shaped (verified against the live specs this session: RFC 9449 binds a token to
the SHA-256 JWK thumbprint of the client's key via a ``cnf`` claim, and the
resource verifies the thumbprint of the key that signed the per-request proof
matches that ``cnf``).

A Tex-issued credential can be *sender-constrained*: it carries a ``cnf`` (RFC
7800 confirmation) claim holding the RFC 7638 JWK SHA-256 thumbprint of a public
key the holder controls. To USE such a credential the holder presents a
short-lived PoP proof — a small Ed25519-signed object — and the verifier checks
that

  (a) the proof's signature verifies under the *presented* public key,
  (b) that key's RFC-7638 thumbprint equals the credential's ``cnf.jkt``,
  (c) the proof is bound to this exact context (``bind`` — the credential token
      for resource use, or the exchange request for token-exchange), and
  (d) the proof is fresh (``iat`` within a tight window).

This is the DPoP property: a *stolen credential is useless* without the holder's
private key. The key never leaves the holder; Tex only ever sees the public
thumbprint, so this is consistent with the "agent holds no standing keys handed
out by Tex" doctrine — the holder's PoP key is its own, not a Tex-minted secret.

Honesty / boundary (do not overstate):
  * This module *verifies* a PoP proof. It does NOT make a third-party resource
    DEMAND one — that is deployment (the resource must require the proof header
    and pin Tex as issuer). See ``tex.authority.broker`` SUMMARY.
  * Residual replay: a captured proof can be replayed within its freshness
    window against the SAME ``bind`` context. RFC 9449 closes this with a
    server-side ``jti`` cache; ``verify_pop_proof`` returns the proof ``jti`` so a
    resource can dedupe, but this stateless verifier keeps no such cache.
    Labeled, not hidden.
  * Ed25519 is classical (pre-quantum). ``research-solid`` for today's threat
    model; not PQ. The credential MAC and the PoP key are independent — a PQ PoP
    key would slot in here without touching the broker.

Citation honesty: RFC 8693 / 7800 / 9449 were verified against the live specs
this session. RFC 7638 (JWK thumbprint) and RFC 8037 (OKP/Ed25519 JOSE) are
cited ``UNVERIFIED-FROM-MEMORY`` (not re-fetched this session). The thumbprint
is implemented to the RFC-7638 shape (SHA-256 over the lexicographically-sorted
required members ``{crv,kty,x}``) and is byte-for-byte *internally* consistent
across mint/exchange/use (the tests prove that); it has NOT been validated
against an external reference vector, so interop with a third-party DPoP
resource server is ``UNVERIFIED`` until checked against one.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import time
from dataclasses import dataclass
from typing import Any

__all__ = [
    "public_jwk",
    "jwk_thumbprint",
    "load_public_key",
    "raw_public_bytes",
    "thumbprint",
    "new_jti",
    "make_pop_proof",
    "PopResult",
    "verify_pop_proof",
]


# --------------------------------------------------------------------------- #
# Codec helpers (b64url no-pad; canonical JSON) — same discipline as permit.py #
# --------------------------------------------------------------------------- #


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64url_decode(text: str) -> bytes:
    pad = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + pad)


def _canonical(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


# --------------------------------------------------------------------------- #
# JWK + RFC 7638 thumbprint (Ed25519 / OKP, RFC 8037)                          #
# --------------------------------------------------------------------------- #


def public_jwk(raw_public_key: bytes) -> dict[str, str]:
    """The OKP/Ed25519 JWK for a raw 32-byte public key (RFC 8037)."""
    return {"crv": "Ed25519", "kty": "OKP", "x": _b64url(raw_public_key)}


def jwk_thumbprint(jwk: dict[str, Any]) -> str:
    """RFC 7638 JWK SHA-256 thumbprint (b64url), over the required members only.

    For an OKP key the required members are ``crv``, ``kty``, ``x`` — serialized
    as the lexicographically-sorted, whitespace-free JSON the RFC mandates.
    """
    required = {"crv": jwk["crv"], "kty": jwk["kty"], "x": jwk["x"]}
    digest = hashlib.sha256(_canonical(required).encode("utf-8")).digest()
    return _b64url(digest)


def load_public_key(jwk: dict[str, Any]) -> Any:
    """Reconstruct an ``Ed25519PublicKey`` from an OKP JWK. Raises on bad input."""
    if not isinstance(jwk, dict) or jwk.get("kty") != "OKP" or jwk.get("crv") != "Ed25519":
        raise ValueError("unsupported JWK (expected OKP/Ed25519)")
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    return Ed25519PublicKey.from_public_bytes(_b64url_decode(str(jwk["x"])))


def raw_public_bytes(public_key: Any) -> bytes:
    """The raw 32-byte public key for an ``Ed25519PublicKey``."""
    from cryptography.hazmat.primitives import serialization

    return public_key.public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )


def thumbprint(public_key: Any) -> str:
    """RFC 7638 thumbprint of an ``Ed25519PublicKey``.

    All thumbprints (mint-time, exchange-time, use-time) flow through this one
    path so they are byte-for-byte consistent regardless of how the key arrived
    (raw bytes vs a JWK that may or may not have carried b64 padding).
    """
    return jwk_thumbprint(public_jwk(raw_public_bytes(public_key)))


def new_jti() -> str:
    """A fresh one-time-use proof id (URL-safe)."""
    return secrets.token_urlsafe(18)


# --------------------------------------------------------------------------- #
# Proof creation (holder side / tests) and verification (resource / Tex side)  #
# --------------------------------------------------------------------------- #


def make_pop_proof(
    private_key: Any,
    *,
    bind: str,
    now: float | None = None,
    challenge: str | None = None,
    jti: str | None = None,
) -> str:
    """Create a PoP proof: a ``b64url(body).b64url(sig)`` Ed25519 token.

    ``bind`` is the context string the proof is locked to (the broker computes it
    from the credential token for resource use, or the exchange request for token
    exchange). ``challenge`` (optional) lets a resource inject a server nonce.
    Holder-side helper; the private key never leaves the holder.
    """
    raw_pub = raw_public_bytes(private_key.public_key())
    body: dict[str, Any] = {
        "jwk": public_jwk(raw_pub),
        "bind": bind,
        "iat": int(now if now is not None else time.time()),
        "jti": jti or new_jti(),
    }
    if challenge is not None:
        body["chal"] = challenge
    body_bytes = _canonical(body).encode("utf-8")
    sig = private_key.sign(body_bytes)
    return f"{_b64url(body_bytes)}.{_b64url(sig)}"


@dataclass(frozen=True, slots=True)
class PopResult:
    ok: bool
    reason: str
    jti: str | None = None


def verify_pop_proof(
    proof: str | None,
    *,
    cnf_jkt: str,
    bind: str,
    now: float | None = None,
    max_age: int = 120,
    max_skew: int = 5,
    expected_challenge: str | None = None,
) -> PopResult:
    """Verify a PoP proof against an expected ``cnf`` thumbprint and ``bind``.

    Never raises; any defect is a not-ok result. The signature is verified over
    the EXACT transmitted bytes (not a re-serialization), so a canonicalization
    quirk can never let a tampered body slip through.
    """
    try:
        if not proof or "." not in proof:
            return PopResult(False, "malformed pop proof")
        body_b64, _, sig_b64 = proof.partition(".")
        body_bytes = _b64url_decode(body_b64)
        body = json.loads(body_bytes)
        if not isinstance(body, dict):
            return PopResult(False, "malformed pop body")

        jwk = body.get("jwk")
        if not isinstance(jwk, dict):
            return PopResult(False, "missing pop key")
        try:
            pub = load_public_key(jwk)
        except Exception:  # noqa: BLE001 — any load failure fails closed
            return PopResult(False, "unsupported pop key")

        # (a) signature must verify under the PRESENTED key over the exact bytes.
        try:
            pub.verify(_b64url_decode(sig_b64), body_bytes)
        except Exception:  # noqa: BLE001 — bad signature fails closed
            return PopResult(False, "bad pop signature")

        # (b) the presented key's thumbprint must equal the credential's cnf.jkt.
        if not hmac.compare_digest(thumbprint(pub), str(cnf_jkt or "")):
            return PopResult(False, "cnf thumbprint mismatch")

        # (c) context binding — locks the proof to this token / exchange request.
        if not hmac.compare_digest(str(body.get("bind") or ""), str(bind)):
            return PopResult(False, "pop binding mismatch")

        # (d) freshness.
        clock = now if now is not None else time.time()
        try:
            iat = int(body.get("iat"))
        except (TypeError, ValueError):
            return PopResult(False, "pop iat invalid")
        if iat > int(clock) + max_skew:
            return PopResult(False, "pop not yet valid")
        if iat < int(clock) - max_age:
            return PopResult(False, "pop expired")

        if expected_challenge is not None and body.get("chal") != expected_challenge:
            return PopResult(False, "pop challenge mismatch")

        jti = body.get("jti")
        return PopResult(True, "ok", jti=str(jti) if jti else None)
    except Exception:  # noqa: BLE001 — never raise out of verify
        return PopResult(False, "pop verification error")
