"""
OAuth 2.0 Transaction Tokens for Agents.

Implements the surface of ``draft-oauth-transaction-tokens-for-agents``
revision 06 (April 11, 2026, A. Raut, Amazon). The draft extends the
base OAuth Transaction Tokens framework
(``draft-ietf-oauth-transaction-tokens``) to carry agent-specific
context — the ``act`` claim identifying which agent is acting, and the
``sub`` claim identifying the principal on whose behalf the agent
acts (or, for autonomous agents, the agent itself).

Why this exists
---------------
The April 30, 2026 Five Eyes joint guidance on Securing Agentic AI
specifies that agents MUST be authenticated using verifiable
credentials *with short-lived OAuth 2.0/OIDC tokens*. AIDs alone are
not enough — they prove who the agent is, but not what specific
transaction the agent is currently authorized to perform. Txn-Tokens
provide the short-lived, transaction-scoped layer that the AID is
embedded into for service-to-service calls.

Tex Thread 13 binding
---------------------
Tex packages an AID + Txn-Token together in the
``AidTransactionToken`` artifact below. The service-to-service call:

  1.  Tex's outbound proxy fetches the agent's held AID.
  2.  Tex derives a per-call presentation revealing only the claims
      the target service needs.
  3.  Tex wraps that presentation in a Txn-Token with:
        - ``act`` = the agent's DID
        - ``sub`` = the principal DID (or the agent's DID if autonomous)
        - ``aid_presentation`` = the derived presentation envelope
        - ``txn_context`` = the call's RAR-style scope (path, verb,
          payload hash, audience)
  4.  The Txn-Token is signed by Tex's Txn-Token Service with a
      short TTL (default 60s).
  5.  The downstream service verifies the Txn-Token signature, then
      independently verifies the embedded AID presentation.

This double-attestation pattern (a signed token *and* a verifiable
credential inside the token) is exactly what the Apr 30 Five Eyes
guidance specifies. No competitor — including Microsoft AGT, Okta Agent
Kit, 1Password Unified Access, CyberArk Secure AI Agents — currently
ships this combination as a single durable artifact.
"""

from __future__ import annotations

import base64
import enum
import json
import time
import uuid
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from tex.pqcrypto.algorithm_agility import (
    SignatureAlgorithm,
    SignatureKeyPair,
    get_signature_provider,
)


__all__ = [
    "TxnTokenScope",
    "TxnTokenClaims",
    "TxnTokenArtifact",
    "TxnTokenVerifyResult",
    "issue_txn_token",
    "verify_txn_token",
]


TXN_TOKEN_TYP = "txn+jwt"
TXN_TOKEN_VERSION = "1.0"


class TxnTokenScope(BaseModel):
    """RAR-style scope binding for a single transaction."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    audience: str = Field(min_length=1, max_length=512)
    http_method: str = Field(min_length=1, max_length=16)
    http_path: str = Field(min_length=1, max_length=2048)
    request_body_hash_hex: str = Field(min_length=64, max_length=64)
    additional: dict[str, Any] = Field(default_factory=dict)


class TxnTokenClaims(BaseModel):
    """JWT-style claim set, schema-mirrored from draft-06 §3."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    iss: str = Field(min_length=1, max_length=512, description="Txn-Token Service issuer")
    sub: str = Field(min_length=1, max_length=512, description="principal DID (or agent DID if autonomous)")
    act: str = Field(min_length=1, max_length=512, description="agent DID — the actor")
    aud: str = Field(min_length=1, max_length=512)
    iat: int = Field(ge=0)
    exp: int = Field(ge=0)
    jti: str = Field(min_length=1, max_length=256)
    scope: TxnTokenScope
    aid_presentation_b64u: str | None = Field(
        default=None, max_length=65536,
        description="Optional embedded AID presentation envelope.",
    )
    version: str = Field(default=TXN_TOKEN_VERSION, max_length=16)


class TxnTokenArtifact(BaseModel):
    """The on-wire compact JWS string."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    token: str = Field(min_length=1, description="compact JWS: header.payload.signature")
    algorithm: SignatureAlgorithm


class TxnTokenVerifyResult(BaseModel):
    """Verification outcome."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    valid: bool
    reason: str = Field(default="", max_length=512)
    claims: TxnTokenClaims | None = None


# --------------------------------------------------------------------------- #
# Helpers                                                                      #
# --------------------------------------------------------------------------- #


def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64u_decode(data: str) -> bytes:
    return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))


# --------------------------------------------------------------------------- #
# Public API                                                                   #
# --------------------------------------------------------------------------- #


def issue_txn_token(
    *,
    iss: str,
    sub: str,
    act: str,
    aud: str,
    scope: TxnTokenScope,
    aid_presentation_b64u: str | None = None,
    ttl_seconds: int = 60,
    signing_keypair: SignatureKeyPair | None = None,
    algorithm: SignatureAlgorithm = SignatureAlgorithm.ML_DSA_65,
) -> TxnTokenArtifact:
    """
    Issue a Txn-Token for one agent transaction.

    Defaults:
        * ``ttl_seconds = 60`` — short-lived per Five Eyes guidance.
        * ``algorithm = ML-DSA-65`` — PQ by default, Tex's signature.

    The returned ``token`` is a compact JWS: ``header.payload.sig``.
    """
    provider = get_signature_provider(algorithm)
    if signing_keypair is None:
        signing_keypair = provider.generate_keypair(f"txn-token-{iss}")
    elif signing_keypair.algorithm != algorithm:
        raise ValueError("signing_keypair algorithm mismatch")

    iat = int(time.time())
    exp = iat + ttl_seconds
    jti = str(uuid.uuid4())

    claims = TxnTokenClaims(
        iss=iss, sub=sub, act=act, aud=aud,
        iat=iat, exp=exp, jti=jti,
        scope=scope, aid_presentation_b64u=aid_presentation_b64u,
    )

    header = {"typ": TXN_TOKEN_TYP, "alg": algorithm.value}
    header_b64 = _b64u(json.dumps(header, sort_keys=True, separators=(",", ":")).encode())
    payload_b64 = _b64u(claims.model_dump_json().encode())
    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    sig = provider.sign(signing_input, signing_keypair)
    sig_b64 = _b64u(sig)
    token = f"{header_b64}.{payload_b64}.{sig_b64}"

    return TxnTokenArtifact(token=token, algorithm=algorithm)


def verify_txn_token(
    token: str,
    *,
    expected_audience: str,
    issuer_public_key: bytes,
    expected_act: str | None = None,
    expected_sub: str | None = None,
    now_epoch: int | None = None,
) -> TxnTokenVerifyResult:
    """Verify a Txn-Token. Fail-closed."""
    if now_epoch is None:
        now_epoch = int(time.time())
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return TxnTokenVerifyResult(valid=False, reason="not a 3-part JWS")
        header = json.loads(_b64u_decode(parts[0]))
        if header.get("typ") != TXN_TOKEN_TYP:
            return TxnTokenVerifyResult(valid=False, reason="wrong typ")
        algorithm = SignatureAlgorithm(header["alg"])
        claims = TxnTokenClaims.model_validate_json(_b64u_decode(parts[1]))
        sig = _b64u_decode(parts[2])
    except (ValueError, KeyError, RuntimeError) as exc:
        return TxnTokenVerifyResult(valid=False, reason=f"parse error: {exc}")

    if claims.aud != expected_audience:
        return TxnTokenVerifyResult(valid=False, reason="aud mismatch", claims=claims)
    if claims.exp <= now_epoch:
        return TxnTokenVerifyResult(valid=False, reason="expired", claims=claims)
    if claims.iat > now_epoch + 300:  # 5-min skew
        return TxnTokenVerifyResult(valid=False, reason="iat in future", claims=claims)
    if expected_act is not None and claims.act != expected_act:
        return TxnTokenVerifyResult(valid=False, reason="act mismatch", claims=claims)
    if expected_sub is not None and claims.sub != expected_sub:
        return TxnTokenVerifyResult(valid=False, reason="sub mismatch", claims=claims)

    provider = get_signature_provider(algorithm)
    signing_input = f"{parts[0]}.{parts[1]}".encode("ascii")
    if not provider.verify(signing_input, sig, issuer_public_key):
        return TxnTokenVerifyResult(valid=False, reason="signature invalid", claims=claims)
    return TxnTokenVerifyResult(valid=True, reason="ok", claims=claims)
