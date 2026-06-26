"""B3 — the resource-side (PEP) offline TG-PCC verifier.

A downstream RESOURCE (the actuator / "demand" side) imports this module to
DEMAND a Tex-issued capability token (a TG-PCC) before it acts. ``verify_tgpcc``
is a PURE, AIR-GAPPED function over four offline inputs:

  * the PRESENTED token (the TG-PCC artifact the caller hands over),
  * the PRESENTED call ``(method, resource, params)`` — what the caller is
    actually asking the resource to do,
  * the PRESENTED DPoP/PoP proof (holder possession), and
  * a PINNED-LOCAL JWKS dict (fetched ONCE from the issuer's
    ``/.well-known/tex-jwks.json`` at config time, NEVER per request).

It returns ``ResourceCheck(ok, reason, ...)`` and DEFAULT-DENIES: no token, an
unverifiable leg, or any missing input is a denial — never a bypass.

IMPORT-PURITY CONTRACT (load-bearing — see ``__init__.py`` and the purity test)
---------------------------------------------------------------------------
A downstream resource must be able to import this verifier WITHOUT dragging in
the Tex app / PDP / proxy / governance runtime. Importing ``tex.authority.broker``
(or even ``tex.authority.pop`` / ``tex.authority.taint_label``) pulls ~1300
modules including numpy, scipy, starlette, and ``tex.engine.pdp`` — because of
package ``__init__`` side-effects, NOT because the verify *logic* is heavy. So
this module imports ONLY the standard library and ``cryptography``'s Ed25519
primitive. The verify ALGORITHM is a faithful re-expression of the audited
``broker.verify_with_jwks`` / ``broker.verify_prov_commit_floor`` /
``pop.verify_pop_proof`` — it reinvents NO crypto, it ports already-proven byte
discipline (sort-keys canonical JSON, b64url, domain-separated Ed25519 signing
string, RFC-7638 thumbprint). The byte-for-byte parity is pinned by the tests in
``tests/pep/test_resource_verify.py`` against real broker-minted tokens.

HONESTY (do NOT relabel)
------------------------
This is DEMAND-VERIFICATION AT AN IN-PATH RESOURCE, NOT un-bypassable
enforcement. If the resource can be reached by a route that does NOT traverse
this verifier (a raw API key, an alternate port, a direct socket), the
non-bypassable property is POSITIONAL-ONLY — the same limit Entra / Faramesh /
SatGate concede. The verifier SHAPE itself is PARITY: an offline public-key +
intent-bind + holder-bind check is the deployed shape AttestMCP / AIP / Biscuit
/ Vouchsafe already ship. B3 owns NO novel mechanism. What makes the COMPOSITE
beyond-frontier lives entirely UPSTREAM, in the taint-gated MINT (B1+): a check
of the ``prov_commit`` integrity floor — a check no shipped demand-verifier does
because no shipped minter puts a gated provenance label INSIDE the signed token.
B3 merely re-checks that floor offline. Its novelty is INHERITED, not its own.

Default-OFF: the TG-PCC plane is dark unless the issuer ran with ``TEX_TGPCC=1``
and a pinned signing key, so the published JWKS is ``{"keys": []}`` by default
and this verifier then DENIES every token ("no matching key") — the correct
fail-closed posture, not a bug.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from dataclasses import dataclass
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

__all__ = [
    "ResourceCheck",
    "PresentedRequest",
    "verify_tgpcc",
    "verify_capability_token",
    "verify_prov_commit_floor",
    "canonical_intent_commit",
]

# --------------------------------------------------------------------------- #
# Constants ported (NOT imported) from the authority plane — kept in lock-step #
# with broker.py / taint_label.py by the parity tests. Importing the originals #
# would contaminate the import graph (see module docstring).                   #
# --------------------------------------------------------------------------- #

# JOSE/RFC-8037 name for Ed25519 — what the published JWKS advertises as ``alg``
# and what the signed claims carry (so the algorithm is integrity-protected).
_CLAIM_ALG_ED25519 = "EdDSA"
# Domain-separation prefix for the Ed25519 signing leg (broker._AUTHORITY_ED25519
# _DOMAIN). The signature covers ``"{domain}.{body}"`` so an HMAC body and an
# Ed25519 body can never cross-verify.
_AUTHORITY_ED25519_DOMAIN = "texauth.ed25519.v1"
# The ``enc`` tag pinning the prov_commit numeric encoding (taint_label
# .PROV_COMMIT_ENC). Inlined as a literal so the resource never imports
# tex.authority.taint_label (heavy package).
_PROV_COMMIT_ENC = "camel.fides.v1"
# PoP ``bind`` prefix for RESOURCE USE (broker._use_binding). Locks a DPoP proof
# to the exact credential token being presented.
_POP_USE_PREFIX = "tex-pop-use:"
# Freshness window for the holder proof (mirrors pop.verify_pop_proof defaults).
_POP_MAX_AGE = 120
_POP_MAX_SKEW = 5


# --------------------------------------------------------------------------- #
# Result + presented-request shapes                                           #
# --------------------------------------------------------------------------- #


@dataclass(frozen=True, slots=True)
class ResourceCheck:
    """The verdict of demanding + verifying a TG-PCC at a resource.

    Mirrors ``broker.CredentialCheck`` but is a LOCAL type so this module needs
    no tex.authority import. Never carries a secret. ``ok`` is the PERMIT/DENY
    decision; ``reason`` is the fail-closed reason string (preserved verbatim
    from the first failing leg); ``claims`` is the SIGNED claim dict on success;
    ``jti`` is the holder-proof one-time id (so a resource may dedupe replays —
    this verifier is stateless and keeps NO jti cache, see README residual-replay
    note).
    """

    ok: bool
    reason: str
    claims: dict[str, Any] | None = None
    binding: str | None = None
    jti: str | None = None


@dataclass(frozen=True, slots=True)
class PresentedRequest:
    """The call the presenter is ACTUALLY making at the resource.

    ``verify_tgpcc`` recomputes the intent commitment from THIS — so altering
    ``params`` after the token was minted breaks the bind (Intent-Bind). The
    field mapping mirrors the minter (governance_standing_routes.py): the route
    commits ``canonical_intent_commit(intent_method or action_type, intent_resource
    or audience, intent_params or {})`` — so a resource must present the SAME
    (method, resource, params) triple.
    """

    method: str
    resource: str
    params: Any = None


# --------------------------------------------------------------------------- #
# Ported pure helpers (stdlib + cryptography only)                            #
# --------------------------------------------------------------------------- #


def _b64url_decode(data: str) -> bytes:
    """URL-safe base64 decode with padding restored (port of permit._b64url_decode)."""
    pad = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + pad)


def _b64url(data: bytes) -> str:
    """URL-safe base64 encode, no padding (port of pop._b64url)."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _canonical(obj: Any) -> str:
    """Canonical JSON: sorted keys, compact separators (port of permit._canonical)."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


def canonical_intent_commit(method: str, resource: str, params: Any) -> str:
    """SHA-256 hex over canonical ``(method, resource, params)`` — byte-for-byte
    identical to ``broker.canonical_intent_commit`` so the recomputed commitment
    matches the minted one. Order-insensitive in ``params`` keys."""
    canonical_json = json.dumps(
        {"method": method, "resource": resource, "params": params},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(canonical_json).hexdigest()


def _public_jwk(raw_public_key: bytes) -> dict[str, str]:
    """OKP/Ed25519 JWK for a raw 32-byte public key (port of pop.public_jwk)."""
    return {"crv": "Ed25519", "kty": "OKP", "x": _b64url(raw_public_key)}


def _jwk_thumbprint(jwk: dict[str, Any]) -> str:
    """RFC-7638 JWK SHA-256 thumbprint (port of pop.jwk_thumbprint).

    Over the required OKP members ``{crv, kty, x}`` only, serialized as the
    lexicographically-sorted, whitespace-free JSON the RFC mandates.
    """
    required = {"crv": jwk["crv"], "kty": jwk["kty"], "x": jwk["x"]}
    digest = hashlib.sha256(_canonical(required).encode("utf-8")).digest()
    return _b64url(digest)


def _load_public_key(jwk: dict[str, Any]) -> Ed25519PublicKey:
    """Reconstruct an Ed25519PublicKey from an OKP JWK (port of pop.load_public_key)."""
    if (
        not isinstance(jwk, dict)
        or jwk.get("kty") != "OKP"
        or jwk.get("crv") != "Ed25519"
    ):
        raise ValueError("unsupported JWK (expected OKP/Ed25519)")
    return Ed25519PublicKey.from_public_bytes(_b64url_decode(str(jwk["x"])))


def _raw_public_bytes(public_key: Ed25519PublicKey) -> bytes:
    """The raw 32-byte public key (port of pop.raw_public_bytes)."""
    from cryptography.hazmat.primitives import serialization

    return public_key.public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )


def _thumbprint(public_key: Ed25519PublicKey) -> str:
    """RFC-7638 thumbprint of an Ed25519PublicKey (port of pop.thumbprint).

    Flows through ``_public_jwk(_raw_public_bytes(...))`` so it is byte-for-byte
    consistent with the mint-time thumbprint regardless of how the key arrived.
    """
    return _jwk_thumbprint(_public_jwk(_raw_public_bytes(public_key)))


def _use_binding(token: str) -> str:
    """PoP ``bind`` for RESOURCE USE (port of broker._use_binding).

    Locks a DPoP proof to THIS exact credential token. The token already commits
    aud/act/scope, so binding to it covers them.
    """
    return _POP_USE_PREFIX + hashlib.sha256(token.encode("utf-8")).hexdigest()


def _select_jwk(jwks: dict[str, Any], kid: str | None) -> dict[str, Any] | None:
    """Pick the verifying JWK from a PINNED JWKS, fail-closed (port of
    broker._select_jwk).

    Filter to OKP/EdDSA signing keys; a named ``kid`` that matches nothing is a
    HARD miss (never "try any key"); a missing ``kid`` resolves only when exactly
    one candidate exists. Pure dict lookup — no network.
    """
    keys = jwks.get("keys") if isinstance(jwks, dict) else None
    if not isinstance(keys, list):
        return None
    candidates = [
        k
        for k in keys
        if isinstance(k, dict)
        and k.get("kty") == "OKP"
        and k.get("crv") == "Ed25519"
        and k.get("use", "sig") == "sig"
        and k.get("alg", _CLAIM_ALG_ED25519) == _CLAIM_ALG_ED25519
    ]
    if not candidates:
        return None
    if kid:
        for k in candidates:
            if hmac.compare_digest(str(k.get("kid", "")), str(kid)):
                return k
        return None  # named kid miss => fail closed
    return candidates[0] if len(candidates) == 1 else None


def _verify_cred_ed25519(
    public_key: Ed25519PublicKey, body: str, sig_b64: str
) -> bool:
    """Verify the Ed25519 credential signature over the domain-separated body
    (port of broker._verify_cred_ed25519). Returns False on any defect."""
    msg = f"{_AUTHORITY_ED25519_DOMAIN}.{body}".encode("ascii")
    try:
        public_key.verify(_b64url_decode(sig_b64), msg)
        return True
    except Exception:  # noqa: BLE001 — InvalidSignature & any defect fail closed
        return False


# --------------------------------------------------------------------------- #
# verify_capability_token — port of broker.verify_with_jwks                    #
# --------------------------------------------------------------------------- #


def verify_capability_token(
    token: str | None,
    jwks: dict[str, Any],
    *,
    pinned_epoch: int | None = None,
    expected_issuer: str | None = None,
    now: float | None = None,
    expected_intent_commit: str | None = None,
) -> ResourceCheck:
    """Pure, offline (AIR-GAPPED) verify of a Tex Ed25519 capability token.

    A faithful re-expression of ``broker.verify_with_jwks`` over a PINNED LOCAL
    ``jwks`` dict (passed in, NEVER fetched). Resolves ``kid`` -> public key from
    the pinned JWKS, verifies the Ed25519 signature, applies the
    epoch/expiry/nbf/iat/issuer floor, and (when supplied) binds the intent.
    Constructs NO HTTP client, opens NO socket. Never raises.
    """
    try:
        if not token or "." not in token:
            return ResourceCheck(False, "malformed credential")
        body, _, sig = token.partition(".")

        try:
            claims = json.loads(_b64url_decode(body))
        except (ValueError, json.JSONDecodeError):
            return ResourceCheck(False, "unparseable claims")
        if not isinstance(claims, dict):
            return ResourceCheck(False, "unparseable claims")

        if claims.get("alg") != _CLAIM_ALG_ED25519:
            # This pure verifier is for the asymmetric leg only (an HMAC token has
            # no published JWKS key and cannot be checked offline).
            return ResourceCheck(False, "unsupported alg", claims)

        kid = claims.get("kid")
        jwk = _select_jwk(jwks, kid)
        if jwk is None:
            return ResourceCheck(False, "no matching key", claims)
        try:
            public_key = _load_public_key(jwk)
        except Exception:  # noqa: BLE001
            return ResourceCheck(False, "unsupported key", claims)

        if not _verify_cred_ed25519(public_key, body, sig):
            return ResourceCheck(False, "bad signature", claims)

        if pinned_epoch is not None:
            try:
                tok_epoch = int(claims.get("epoch"))
            except (TypeError, ValueError):
                return ResourceCheck(False, "missing epoch", claims)
            if tok_epoch < int(pinned_epoch):
                return ResourceCheck(False, "stale epoch", claims)

        clock = now if now is not None else time.time()
        exp = claims.get("exp")
        if exp is not None and int(exp) < int(clock):
            return ResourceCheck(False, "expired", claims)
        nbf = claims.get("nbf")
        if nbf is not None and int(nbf) > int(clock) + 5:
            return ResourceCheck(False, "not yet valid", claims)
        iat = claims.get("iat")
        if iat is not None and int(iat) > int(clock) + 5:
            return ResourceCheck(False, "not yet valid", claims)

        if expected_issuer is not None and claims.get("iss") != expected_issuer:
            return ResourceCheck(False, "issuer mismatch", claims)

        if expected_intent_commit is not None:
            tok_intent = claims.get("intent_commit")
            if not isinstance(tok_intent, str) or not hmac.compare_digest(
                tok_intent, str(expected_intent_commit)
            ):
                return ResourceCheck(False, "intent mismatch", claims)

        return ResourceCheck(True, "ok", claims, binding=claims.get("bnd"))
    except Exception:  # noqa: BLE001 — never raise out of verify
        return ResourceCheck(False, "verification error")


# --------------------------------------------------------------------------- #
# verify_prov_commit_floor — port of broker.verify_prov_commit_floor           #
# --------------------------------------------------------------------------- #


def verify_prov_commit_floor(claims: dict[str, Any] | None) -> ResourceCheck:
    """Offline re-check of the TG-PCC ``prov_commit`` integrity floor (B1+).

    A faithful re-expression of ``broker.verify_prov_commit_floor``: reads the
    SIGNED ``prov_commit`` from the claims and re-enforces ``label ⊒ floor`` from
    the embedded integer label/floor alone (CaMeL: lower int = more trusted, so
    ⊒ means ``label.integrity <= floor.integrity`` and likewise for
    confidentiality). Fail-closed on missing/malformed/unknown-enc/insufficient.

    This is the ONLY leg whose VALUE is beyond-frontier — and its novelty is
    INHERITED from the minter (B1+): the resource merely re-checks a floor the
    mint already enforced as a precondition of the signature existing. Because
    ``lineage_root`` is a COMMITMENT (not the DAG), this proves "Tex committed to
    this label/floor under its key and the label satisfies the floor", NOT a
    re-derivation of the label from raw operands.
    """
    if not isinstance(claims, dict):
        return ResourceCheck(False, "no prov_commit")
    prov = claims.get("prov_commit")
    if not isinstance(prov, dict):
        return ResourceCheck(False, "no prov_commit", claims)
    if prov.get("enc") != _PROV_COMMIT_ENC:
        return ResourceCheck(False, "unknown prov_commit enc", claims)
    label = prov.get("label")
    floor = prov.get("floor")
    if not isinstance(label, dict) or not isinstance(floor, dict):
        return ResourceCheck(False, "malformed prov_commit", claims)
    try:
        li = int(label["integrity"])
        lc = int(label["confidentiality"])
        fi = int(floor["integrity"])
        fc = int(floor["confidentiality"])
    except (KeyError, TypeError, ValueError):
        return ResourceCheck(False, "malformed prov_commit", claims)
    if li <= fi and lc <= fc:
        return ResourceCheck(True, "ok", claims)
    return ResourceCheck(False, "insufficient_integrity", claims)


# --------------------------------------------------------------------------- #
# Holder (PoP / DPoP) check — port of pop.verify_pop_proof's resource-USE leg  #
# --------------------------------------------------------------------------- #


def _verify_holder_proof(
    proof: str | None,
    *,
    cnf_jkt: str,
    bind: str,
    now: float | None = None,
    max_age: int = _POP_MAX_AGE,
    max_skew: int = _POP_MAX_SKEW,
) -> ResourceCheck:
    """Verify a DPoP/PoP proof binds the PRESENTER to the token's ``cnf.jkt``.

    Faithful re-expression of ``pop.verify_pop_proof``: verifies the proof
    signature under the PRESENTED key over the EXACT transmitted bytes, computes
    that key's RFC-7638 thumbprint and constant-time-compares it to ``cnf_jkt``
    (holder possession), checks ``bind`` (locks to this token) and freshness. The
    holder public key arrives INSIDE the proof body — the resource never needs it
    out-of-band, which is exactly what makes this resource-side possession. Never
    raises. ``ok=False`` is a fail-closed denial.
    """
    try:
        if not proof or "." not in proof:
            return ResourceCheck(False, "pop: malformed pop proof")
        body_b64, _, sig_b64 = proof.partition(".")
        body_bytes = _b64url_decode(body_b64)
        body = json.loads(body_bytes)
        if not isinstance(body, dict):
            return ResourceCheck(False, "pop: malformed pop body")

        jwk = body.get("jwk")
        if not isinstance(jwk, dict):
            return ResourceCheck(False, "pop: missing pop key")
        try:
            pub = _load_public_key(jwk)
        except Exception:  # noqa: BLE001
            return ResourceCheck(False, "pop: unsupported pop key")

        # (a) signature must verify under the PRESENTED key over the exact bytes.
        try:
            pub.verify(_b64url_decode(sig_b64), body_bytes)
        except Exception:  # noqa: BLE001
            return ResourceCheck(False, "pop: bad pop signature")

        # (b) presented key's thumbprint must equal the credential's cnf.jkt
        #     (constant-time) — this IS the holder-possession check.
        if not hmac.compare_digest(_thumbprint(pub), str(cnf_jkt or "")):
            return ResourceCheck(False, "pop: cnf thumbprint mismatch")

        # (c) context binding — locks the proof to this token.
        if not hmac.compare_digest(str(body.get("bind") or ""), str(bind)):
            return ResourceCheck(False, "pop: pop binding mismatch")

        # (d) freshness.
        clock = now if now is not None else time.time()
        try:
            iat = int(body.get("iat"))
        except (TypeError, ValueError):
            return ResourceCheck(False, "pop: pop iat invalid")
        if iat > int(clock) + max_skew:
            return ResourceCheck(False, "pop: pop not yet valid")
        if iat < int(clock) - max_age:
            return ResourceCheck(False, "pop: pop expired")

        jti = body.get("jti")
        return ResourceCheck(True, "ok", jti=str(jti) if jti else None)
    except Exception:  # noqa: BLE001 — never raise out of verify
        return ResourceCheck(False, "pop: pop verification error")


# --------------------------------------------------------------------------- #
# verify_tgpcc — the 7-step assembler. Default-DENY.                           #
# --------------------------------------------------------------------------- #


def verify_tgpcc(
    artifact: Any,
    request: PresentedRequest,
    dpop_proof: str | None,
    jwks: dict[str, Any],
    pinned_epoch: int | None = None,
    *,
    expected_issuer: str | None = None,
    now: float | None = None,
    require_prov_commit: bool = True,
) -> ResourceCheck:
    """DEMAND a TG-PCC and verify it offline, or DENY. The 7-step check.

    ``artifact`` is the presented TG-PCC. It may be the raw compact token string
    (``"body.sig"``) OR an object/dict carrying a ``token`` attribute/key. A
    MISSING artifact is a DENIAL — never a bypass (Demand-Or-Deny).

    The check, in fixed order (each leg reuses the ported primitive above; ZERO
    new crypto):

      0. DEMAND-OR-DENY — no artifact / no token => DENY ("no artifact"). This is
         the leg ``verify_capability_token`` does not own (it takes a token
         directly); B3 owns "no token presented at all".
      1. INTENT (recompute from the PRESENTED request) — derive the expected
         intent commitment from ``request`` (NOT from the token), so altered
         params after mint break the bind.
      2. SIGNATURE + EPOCH + EXPIRY + ISSUER + INTENT-BIND — one
         ``verify_capability_token`` call over the pinned JWKS. ``intent mismatch``
         is the altered-params (confused-deputy) DENY.
      3. HOLDER (cnf.jkt / DPoP) — if the token is sender-constrained, REQUIRE a
         valid DPoP proof whose key thumbprint equals the signed ``cnf.jkt``. A
         token WITH ``cnf`` but no/invalid proof DENIES (never bearer-downgrade).
      4. PROVENANCE FLOOR — re-check ``label ⊒ floor`` from the signed claims.
         Under the TG-PCC default-deny posture (``require_prov_commit=True``) a
         missing/insufficient floor DENIES.
      5/6. (issuer/epoch/exp folded into step 2; optional EAT appraisal is out of
         scope for this leg.)
      7. DEFAULT-DENY — any missing/unverifiable leg above returns DENY with the
         first failing reason preserved.

    Returns ``ResourceCheck(ok=True, "ok", claims, ...)`` only when EVERY demanded
    leg passes. Never raises.
    """
    try:
        # STEP 0 — DEMAND the artifact. Missing token => DENY (not bypass).
        token = _extract_token(artifact)
        if not token:
            return ResourceCheck(False, "no artifact")

        # STEP 1 — recompute the expected intent from the PRESENTED call.
        if request is None:
            return ResourceCheck(False, "no request")
        expected_ic = canonical_intent_commit(
            request.method, request.resource, request.params
        )

        # STEP 2 — signature + epoch + expiry + issuer + intent-bind.
        chk = verify_capability_token(
            token,
            jwks,
            pinned_epoch=pinned_epoch,
            expected_issuer=expected_issuer,
            now=now,
            expected_intent_commit=expected_ic,
        )
        if not chk.ok:
            return chk  # propagate the first failing reason verbatim
        claims = chk.claims or {}

        # STEP 3 — holder (cnf.jkt / DPoP) possession. A sender-constrained token
        # (cnf present, or bnd == "pop") REQUIRES a valid proof — fail-closed, no
        # bearer downgrade. Mirrors broker.verify lines 657-674.
        cnf = claims.get("cnf")
        cnf_jkt = cnf.get("jkt") if isinstance(cnf, dict) else None
        binding = claims.get("bnd")
        pop_jti: str | None = None
        if binding == "pop" or cnf_jkt:
            if not cnf_jkt:
                return ResourceCheck(False, "pop binding without cnf", claims)
            if not dpop_proof:
                return ResourceCheck(False, "pop proof required", claims)
            pr = _verify_holder_proof(
                dpop_proof,
                cnf_jkt=cnf_jkt,
                bind=_use_binding(token),
                now=now,
            )
            if not pr.ok:
                return ResourceCheck(False, pr.reason, claims)
            pop_jti = pr.jti

        # STEP 4 — provenance integrity floor (the leg whose VALUE is inherited
        # from B1+). Under the default-deny TG-PCC posture this is REQUIRED.
        if require_prov_commit:
            floor_chk = verify_prov_commit_floor(claims)
            if not floor_chk.ok:
                return ResourceCheck(False, floor_chk.reason, claims)

        # STEP 5/7 — every demanded leg passed => PERMIT.
        return ResourceCheck(
            True, "ok", claims, binding=chk.binding, jti=pop_jti
        )
    except Exception:  # noqa: BLE001 — never raise; an unexpected error is a DENY.
        return ResourceCheck(False, "verification error")


def _extract_token(artifact: Any) -> str | None:
    """Pull the compact token string out of whatever the resource presented.

    Accepts a raw ``"body.sig"`` string, an object with a ``.token`` attribute
    (e.g. ``MintedCredential``), or a mapping with a ``"token"`` /
    ``"access_token"`` key. Anything else (or empty) => None => DENY at step 0.
    """
    if artifact is None:
        return None
    if isinstance(artifact, str):
        return artifact or None
    if isinstance(artifact, dict):
        tok = artifact.get("token") or artifact.get("access_token")
        return str(tok) if tok else None
    tok = getattr(artifact, "token", None)
    return str(tok) if tok else None
