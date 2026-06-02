"""
SD-JWT VC — Selective-Disclosure JWT Verifiable Credential + SD-Card.

Implements two related drafts in a single module:

*   ``draft-ietf-oauth-sd-jwt-vc-16`` (April 24, 2026, Terbu/Fett/Campbell) —
    the IETF SD-JWT VC base format for JSON-payload verifiable
    credentials with selective disclosure.

*   ``draft-nandakumar-agent-sd-jwt-02`` (Feb 28, 2026, Nandakumar/Jennings,
    Cisco) — **SD-Card**, an SD-JWT encoding of an A2A Agent Card that
    enables selective disclosure of agent capabilities, contact
    information, and operational metadata while maintaining
    cryptographic integrity and preventing correlation across different
    interaction contexts.

Why this matters
----------------
A2A v1.0 Signed Agent Cards (Linux Foundation, GA April 9, 2026) bind
agent discovery to a single ECDSA-signed Card. The SD-Card layer adds:

1.  **Selective disclosure of card fields.** A discovering agent only
    sees the capabilities relevant to its request; competitors discover
    less about the agent's full surface.

2.  **Cross-context unlinkability.** Two presentations of disjoint
    fields cannot be correlated.

3.  **Key-binding.** The card includes a holder-binding key so the
    presenter cannot be impersonated by an intermediary who replays
    a card it intercepted.

Tex's hook
----------
When an AID is issued, Tex can simultaneously emit an SD-Card so the
agent can be discovered via A2A while disclosing only operationally
necessary fields. The SD-Card and the AID share the same underlying
key material via algorithm_agility but live in distinct artifacts —
the SD-Card optimizes for the A2A discovery wire format, the AID
optimizes for governance / compliance.

This is the **first Python implementation of SD-Card** the author is
aware of as of May 18, 2026. Existing implementations are all in TS
(MATTR's library) or Java (walt.id Enterprise Stack) and target
``draft-13`` of the base SD-JWT VC — not the latest ``-16`` revision
nor the SD-Card extension. Tex tracks the latest revision because the
spec changed materially between -13 and -16 (the Claim Metadata
section, including ``Claim Selective Disclosure Metadata``, was added).

References
----------
*   draft-ietf-oauth-sd-jwt-vc-16, §4.6 (Claim Selective Disclosure Metadata).
*   draft-nandakumar-agent-sd-jwt-02, §3 (SD-Card format definition).
*   A2A v1.0 Signed Agent Cards spec.
"""

from __future__ import annotations

import base64
import enum
import hashlib
import json
import secrets
import time
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from tex.pqcrypto.algorithm_agility import (
    SignatureAlgorithm,
    SignatureKeyPair,
    get_signature_provider,
)


__all__ = [
    "SdJwtClaimVisibility",
    "SdJwtVc",
    "SdJwtVcDisclosure",
    "SdJwtVcPresentation",
    "issue_sd_jwt_vc",
    "verify_sd_jwt_vc",
    "present_sd_jwt_vc",
    "verify_sd_jwt_vc_presentation",
    "issue_sd_card",
]


SD_JWT_VC_TYP = "vc+sd-jwt"
SD_CARD_TYP = "sd-card+sd-jwt"


# --------------------------------------------------------------------------- #
# Claim metadata (per §4.6 of draft-16)                                        #
# --------------------------------------------------------------------------- #


class SdJwtClaimVisibility(str, enum.Enum):
    """
    Selective-disclosure visibility per §4.6.4.

    * ``always``    — always disclosed (the issuer cannot remove it).
    * ``allowed``   — may be selectively disclosed by the holder.
    * ``never``     — must never appear in any disclosure (issuer's
                       internal use only). The issuer redacts these
                       before signing.
    """

    ALWAYS = "always"
    ALLOWED = "allowed"
    NEVER = "never"


# --------------------------------------------------------------------------- #
# Pydantic models                                                              #
# --------------------------------------------------------------------------- #


class SdJwtVcDisclosure(BaseModel):
    """One salted disclosure tuple per §4.2.1."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    salt_b64u: str = Field(min_length=22)
    claim_name: str = Field(min_length=1)
    claim_value_json: str = Field(min_length=1, description="canonical JSON")
    digest_b64u: str = Field(min_length=43, max_length=43, description="SHA-256 b64u of disclosure")


class SdJwtVc(BaseModel):
    """
    A held SD-JWT VC. ``compact`` is the on-wire form. ``disclosures``
    is the holder's stash of selectable disclosure tuples.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    compact: str = Field(min_length=1, description="SD-JWT compact serialization (no presentation)")
    disclosures: tuple[SdJwtVcDisclosure, ...]
    algorithm: SignatureAlgorithm
    holder_public_key_b64u: str | None = Field(default=None)
    typ: str = Field(default=SD_JWT_VC_TYP)


class SdJwtVcPresentation(BaseModel):
    """A holder-derived presentation revealing a subset of claims."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    compact: str = Field(min_length=1, description="Includes selected disclosures and KB-JWT")
    revealed_claim_names: tuple[str, ...]
    audience: str
    issued_at_epoch: int


# --------------------------------------------------------------------------- #
# Helpers                                                                      #
# --------------------------------------------------------------------------- #


def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64u_decode(data: str) -> bytes:
    return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))


def _canonical_disclosure_bytes(salt_b64u: str, name: str, value: Any) -> bytes:
    """Per §4.2.1: base64url([salt, name, value]) JSON-array form."""
    arr = [salt_b64u, name, value]
    return json.dumps(arr, sort_keys=False, separators=(",", ":")).encode("utf-8")


def _digest_b64u(disclosure_bytes: bytes) -> str:
    return _b64u(hashlib.sha256(disclosure_bytes).digest())


# --------------------------------------------------------------------------- #
# Issuance                                                                     #
# --------------------------------------------------------------------------- #


def issue_sd_jwt_vc(
    *,
    issuer: str,
    subject: str,
    vct: str,
    claims: dict[str, Any],
    visibility: dict[str, SdJwtClaimVisibility] | None = None,
    issuer_keypair: SignatureKeyPair | None = None,
    holder_public_key_b64u: str | None = None,
    algorithm: SignatureAlgorithm = SignatureAlgorithm.ML_DSA_65,
    valid_for_seconds: int = 31_536_000,  # 1 year
    typ: str = SD_JWT_VC_TYP,
) -> SdJwtVc:
    """
    Issue an SD-JWT VC.

    Args:
        issuer: ``iss`` claim (DID or URL).
        subject: ``sub`` claim — the entity the VC is about (e.g. the agent DID).
        vct: ``vct`` claim — the VC type identifier (e.g.
            ``"https://w3id.org/tex/v1/vet/aid"``).
        claims: the credential subject claims.
        visibility: per-claim visibility map. Defaults to ``ALLOWED``.
            Top-level claims marked ``NEVER`` are redacted entirely;
            claims marked ``ALWAYS`` are kept as plain JWT claims;
            claims marked ``ALLOWED`` are encoded as ``_sd`` digests
            with disclosure tuples held by the holder.
        issuer_keypair: optional pre-existing keypair.
        holder_public_key_b64u: optional holder-binding key for KB-JWT.
        algorithm: signature algorithm (default ML-DSA-65).
        valid_for_seconds: ``exp`` is ``now + this``.
    """
    if visibility is None:
        visibility = {}
    provider = get_signature_provider(algorithm)
    if issuer_keypair is None:
        issuer_keypair = provider.generate_keypair(f"sdjwt-{issuer}")
    elif issuer_keypair.algorithm != algorithm:
        raise ValueError("issuer_keypair algorithm mismatch")

    iat = int(time.time())
    exp = iat + valid_for_seconds

    payload: dict[str, Any] = {
        "iss": issuer,
        "sub": subject,
        "vct": vct,
        "iat": iat,
        "exp": exp,
    }
    sd_digests: list[str] = []
    disclosures: list[SdJwtVcDisclosure] = []

    for claim_name, claim_value in claims.items():
        vis = visibility.get(claim_name, SdJwtClaimVisibility.ALLOWED)
        if vis is SdJwtClaimVisibility.NEVER:
            continue
        if vis is SdJwtClaimVisibility.ALWAYS:
            payload[claim_name] = claim_value
            continue
        # ALLOWED: encode as SD digest + disclosure tuple
        salt_b64u = _b64u(secrets.token_bytes(16))
        disclosure_bytes = _canonical_disclosure_bytes(salt_b64u, claim_name, claim_value)
        digest = _digest_b64u(disclosure_bytes)
        sd_digests.append(digest)
        disclosures.append(
            SdJwtVcDisclosure(
                salt_b64u=salt_b64u,
                claim_name=claim_name,
                claim_value_json=json.dumps(claim_value, sort_keys=True, separators=(",", ":")),
                digest_b64u=digest,
            )
        )
    if sd_digests:
        payload["_sd"] = sorted(sd_digests)
        payload["_sd_alg"] = "sha-256"

    if holder_public_key_b64u is not None:
        payload["cnf"] = {"jwk": {"kty": "OKP", "key": holder_public_key_b64u}}

    header = {"typ": typ, "alg": algorithm.value}
    header_b64 = _b64u(json.dumps(header, sort_keys=True, separators=(",", ":")).encode())
    payload_b64 = _b64u(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode())
    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    sig = provider.sign(signing_input, issuer_keypair)
    issuer_jwt = f"{header_b64}.{payload_b64}.{_b64u(sig)}"

    # SD-JWT compact form: issuer_jwt~disclosure_1~disclosure_2~...~
    # (final tilde indicates no KB-JWT in the held form; the holder will
    # append one when presenting).
    pieces: list[str] = [issuer_jwt]
    for d in disclosures:
        pieces.append(_b64u(_canonical_disclosure_bytes(
            d.salt_b64u, d.claim_name, json.loads(d.claim_value_json)
        )))
    compact = "~".join(pieces) + "~"

    return SdJwtVc(
        compact=compact,
        disclosures=tuple(disclosures),
        algorithm=algorithm,
        holder_public_key_b64u=holder_public_key_b64u,
        typ=typ,
    )


def issue_sd_card(
    *,
    issuer: str,
    agent_did: str,
    agent_card_claims: dict[str, Any],
    visibility: dict[str, SdJwtClaimVisibility] | None = None,
    issuer_keypair: SignatureKeyPair | None = None,
    holder_public_key_b64u: str | None = None,
    algorithm: SignatureAlgorithm = SignatureAlgorithm.ML_DSA_65,
    valid_for_seconds: int = 31_536_000,
) -> SdJwtVc:
    """
    Issue an SD-Card per draft-nandakumar-agent-sd-jwt-02 §3.

    An SD-Card is an SD-JWT VC with ``vct =
    "https://datatracker.ietf.org/doc/draft-nandakumar-agent-sd-jwt/#sd-card"``
    and ``typ = "sd-card+sd-jwt"``. The claim set follows the A2A
    Agent Card schema (capabilities, contact, operational metadata)
    with each top-level field selectively disclosable.
    """
    return issue_sd_jwt_vc(
        issuer=issuer,
        subject=agent_did,
        vct="https://datatracker.ietf.org/doc/draft-nandakumar-agent-sd-jwt/#sd-card",
        claims=agent_card_claims,
        visibility=visibility,
        issuer_keypair=issuer_keypair,
        holder_public_key_b64u=holder_public_key_b64u,
        algorithm=algorithm,
        valid_for_seconds=valid_for_seconds,
        typ=SD_CARD_TYP,
    )


# --------------------------------------------------------------------------- #
# Verification (full held form, no disclosure)                                 #
# --------------------------------------------------------------------------- #


def verify_sd_jwt_vc(
    sd_jwt: SdJwtVc,
    *,
    issuer_public_key: bytes,
    expected_issuer: str | None = None,
    expected_vct: str | None = None,
    now_epoch: int | None = None,
) -> bool:
    """Verify the issuer signature and basic structure. Fail-closed."""
    if now_epoch is None:
        now_epoch = int(time.time())
    try:
        parts = sd_jwt.compact.split("~")
        if len(parts) < 2:
            return False
        issuer_jwt = parts[0]
        jwt_parts = issuer_jwt.split(".")
        if len(jwt_parts) != 3:
            return False
        header = json.loads(_b64u_decode(jwt_parts[0]))
        payload = json.loads(_b64u_decode(jwt_parts[1]))
        sig = _b64u_decode(jwt_parts[2])
    except (ValueError, RuntimeError):
        return False

    if header.get("typ") not in (SD_JWT_VC_TYP, SD_CARD_TYP):
        return False
    algorithm = SignatureAlgorithm(header["alg"])
    if expected_issuer is not None and payload.get("iss") != expected_issuer:
        return False
    if expected_vct is not None and payload.get("vct") != expected_vct:
        return False
    if int(payload.get("exp", 0)) <= now_epoch:
        return False

    # Verify each disclosure tuple digest is in the _sd list.
    sd_digests_set = set(payload.get("_sd", []))
    for d in sd_jwt.disclosures:
        if d.digest_b64u not in sd_digests_set:
            return False
        # Recompute digest from canonical disclosure bytes
        try:
            value = json.loads(d.claim_value_json)
        except ValueError:
            return False
        recomputed = _digest_b64u(
            _canonical_disclosure_bytes(d.salt_b64u, d.claim_name, value)
        )
        if recomputed != d.digest_b64u:
            return False

    provider = get_signature_provider(algorithm)
    signing_input = f"{jwt_parts[0]}.{jwt_parts[1]}".encode("ascii")
    return provider.verify(signing_input, sig, issuer_public_key)


# --------------------------------------------------------------------------- #
# Presentation derivation                                                      #
# --------------------------------------------------------------------------- #


def present_sd_jwt_vc(
    sd_jwt: SdJwtVc,
    *,
    reveal_claim_names: list[str],
    audience: str,
    holder_signing_keypair: SignatureKeyPair | None = None,
    nonce: str = "",
) -> SdJwtVcPresentation:
    """
    Derive a presentation revealing only ``reveal_claim_names``.

    If the SD-JWT had a holder-binding key (``cnf``), a KB-JWT is
    appended; otherwise the presentation form is just the issuer JWT
    + the chosen disclosures + an empty trailing tilde.

    The KB-JWT (Key Binding JWT) is signed by the *holder* over a hash
    of the SD-JWT and the audience+nonce. It proves the presenter is
    the legitimate holder, not an intermediary replaying the card.
    """
    reveal_set = set(reveal_claim_names)
    parts = sd_jwt.compact.split("~")
    issuer_jwt = parts[0]
    pieces: list[str] = [issuer_jwt]
    for d in sd_jwt.disclosures:
        if d.claim_name in reveal_set:
            try:
                value = json.loads(d.claim_value_json)
            except ValueError as exc:
                raise ValueError(f"corrupted disclosure for {d.claim_name}") from exc
            pieces.append(_b64u(_canonical_disclosure_bytes(d.salt_b64u, d.claim_name, value)))

    iat = int(time.time())
    if sd_jwt.holder_public_key_b64u is not None and holder_signing_keypair is not None:
        sd_hash_b64u = _b64u(hashlib.sha256("~".join(pieces).encode("ascii") + b"~").digest())
        kb_header = {"typ": "kb+jwt", "alg": holder_signing_keypair.algorithm.value}
        kb_payload = {"aud": audience, "iat": iat, "sd_hash": sd_hash_b64u, "nonce": nonce}
        kb_h = _b64u(json.dumps(kb_header, sort_keys=True, separators=(",", ":")).encode())
        kb_p = _b64u(json.dumps(kb_payload, sort_keys=True, separators=(",", ":")).encode())
        provider = get_signature_provider(holder_signing_keypair.algorithm)
        kb_sig = provider.sign(f"{kb_h}.{kb_p}".encode("ascii"), holder_signing_keypair)
        kb_jwt = f"{kb_h}.{kb_p}.{_b64u(kb_sig)}"
        compact = "~".join(pieces) + "~" + kb_jwt
    else:
        compact = "~".join(pieces) + "~"

    return SdJwtVcPresentation(
        compact=compact,
        revealed_claim_names=tuple(reveal_claim_names),
        audience=audience,
        issued_at_epoch=iat,
    )


def verify_sd_jwt_vc_presentation(
    presentation: SdJwtVcPresentation,
    *,
    issuer_public_key: bytes,
    expected_audience: str,
    expected_issuer: str | None = None,
    expected_vct: str | None = None,
    holder_public_key: bytes | None = None,
    now_epoch: int | None = None,
    nonce: str = "",
) -> tuple[bool, dict[str, Any]]:
    """
    Verify a presentation. Returns ``(ok, revealed_claims)``.

    Checks:
        1. Issuer JWT signature.
        2. Each appended disclosure's digest is in the ``_sd`` list of
           the issuer JWT payload.
        3. If a KB-JWT is present, its audience/nonce match and its
           signature verifies under ``holder_public_key``.
        4. ``exp`` claim not in the past.
    """
    if now_epoch is None:
        now_epoch = int(time.time())
    revealed: dict[str, Any] = {}
    try:
        # Split off optional KB-JWT.
        if presentation.compact.endswith("~"):
            body = presentation.compact[:-1]
            kb_jwt = None
        else:
            # KB-JWT is the segment after the last "~"
            last_tilde = presentation.compact.rfind("~")
            body = presentation.compact[:last_tilde]
            kb_jwt = presentation.compact[last_tilde + 1 :]

        parts = body.split("~")
        if not parts:
            return False, {}
        issuer_jwt = parts[0]
        disclosure_parts = parts[1:]

        jwt_parts = issuer_jwt.split(".")
        if len(jwt_parts) != 3:
            return False, {}
        header = json.loads(_b64u_decode(jwt_parts[0]))
        payload = json.loads(_b64u_decode(jwt_parts[1]))
        sig = _b64u_decode(jwt_parts[2])

        if header.get("typ") not in (SD_JWT_VC_TYP, SD_CARD_TYP):
            return False, {}
        algorithm = SignatureAlgorithm(header["alg"])
        if expected_issuer is not None and payload.get("iss") != expected_issuer:
            return False, {}
        if expected_vct is not None and payload.get("vct") != expected_vct:
            return False, {}
        if int(payload.get("exp", 0)) <= now_epoch:
            return False, {}

        provider = get_signature_provider(algorithm)
        signing_input = f"{jwt_parts[0]}.{jwt_parts[1]}".encode("ascii")
        if not provider.verify(signing_input, sig, issuer_public_key):
            return False, {}

        # Walk disclosures and verify each digest is in _sd.
        sd_digests_set = set(payload.get("_sd", []))
        for piece in disclosure_parts:
            if not piece:
                continue
            disclosure_bytes = _b64u_decode(piece)
            digest = _digest_b64u(disclosure_bytes)
            if digest not in sd_digests_set:
                return False, {}
            try:
                arr = json.loads(disclosure_bytes)
                if not (isinstance(arr, list) and len(arr) == 3):
                    return False, {}
                _, name, value = arr
                revealed[str(name)] = value
            except ValueError:
                return False, {}

        # Always-disclosed claims live in the JWT payload directly.
        for k, v in payload.items():
            if k in {"iss", "sub", "vct", "iat", "exp", "_sd", "_sd_alg", "cnf"}:
                continue
            if k not in revealed:
                revealed[k] = v

        # Optional KB-JWT verification.
        if kb_jwt:
            if holder_public_key is None:
                return False, {}
            kb_parts = kb_jwt.split(".")
            if len(kb_parts) != 3:
                return False, {}
            kb_header = json.loads(_b64u_decode(kb_parts[0]))
            kb_payload = json.loads(_b64u_decode(kb_parts[1]))
            kb_sig = _b64u_decode(kb_parts[2])
            if kb_header.get("typ") != "kb+jwt":
                return False, {}
            kb_alg = SignatureAlgorithm(kb_header["alg"])
            if kb_payload.get("aud") != expected_audience:
                return False, {}
            if kb_payload.get("nonce", "") != nonce:
                return False, {}
            expected_sd_hash = _b64u(hashlib.sha256(body.encode("ascii") + b"~").digest())
            if kb_payload.get("sd_hash") != expected_sd_hash:
                return False, {}
            kb_provider = get_signature_provider(kb_alg)
            if not kb_provider.verify(
                f"{kb_parts[0]}.{kb_parts[1]}".encode("ascii"), kb_sig, holder_public_key
            ):
                return False, {}

        return True, revealed
    except (ValueError, RuntimeError):
        return False, {}
