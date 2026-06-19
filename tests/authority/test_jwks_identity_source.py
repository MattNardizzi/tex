"""Unit tests for the JWKS-verifying IdentitySource (Entra-Agent-ID / SPIFFE
JWT-SVID shape).

These pin the REAL part of that source — the JWT signature + iss/aud/exp
verification — using a LOCAL signing key, so no network or live IdP is involved.
The JWKS *fetch* is the honest shim (the injected ``key_provider``); here it is a
static in-memory map, exactly as a pinned trust bundle would be.

Properties pinned:
  * a card signed by a configured key (RS256 and EdDSA) verifies and surfaces the
    agent_id + the RFC-7800 cnf.jwk;
  * an UNKNOWN issuer is rejected (untrusted_issuer) even with a valid signature;
  * a tampered token, a wrong key, ``alg: none``, a wrong-audience, and an expired
    token are each rejected fail-closed;
  * no provider keys (unconfigured) => every token rejected.
"""

from __future__ import annotations

import base64
import json

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from tex.authority.identity_source import (
    JwksIdentitySource,
    StaticJwksProvider,
)


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _int_b64(value: int) -> str:
    length = (value.bit_length() + 7) // 8
    return _b64url(value.to_bytes(length, "big"))


# --------------------------------------------------------------------------- #
# Local signing material (stands in for an IdP's keypair; never touches a net) #
# --------------------------------------------------------------------------- #


class RsaSigner:
    def __init__(self, kid: str = "rsa-1") -> None:
        self.kid = kid
        self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    @property
    def jwk(self) -> dict[str, str]:
        nums = self.key.public_key().public_numbers()
        return {
            "kty": "RSA",
            "kid": self.kid,
            "alg": "RS256",
            "n": _int_b64(nums.n),
            "e": _int_b64(nums.e),
        }

    def sign_jwt(self, payload: dict, *, kid: str | None = None, alg: str = "RS256") -> str:
        header = {"alg": alg, "kid": kid if kid is not None else self.kid, "typ": "JWT"}
        signing_input = f"{_b64url(_json(header))}.{_b64url(_json(payload))}"
        sig = self.key.sign(
            signing_input.encode("ascii"), padding.PKCS1v15(), hashes.SHA256()
        )
        return f"{signing_input}.{_b64url(sig)}"


class EddsaSigner:
    def __init__(self, kid: str = "ed-1") -> None:
        self.kid = kid
        self.key = Ed25519PrivateKey.generate()

    @property
    def jwk(self) -> dict[str, str]:
        raw = self.key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        return {"kty": "OKP", "crv": "Ed25519", "kid": self.kid, "alg": "EdDSA", "x": _b64url(raw)}

    def sign_jwt(self, payload: dict) -> str:
        header = {"alg": "EdDSA", "kid": self.kid, "typ": "JWT"}
        signing_input = f"{_b64url(_json(header))}.{_b64url(_json(payload))}"
        sig = self.key.sign(signing_input.encode("ascii"))
        return f"{signing_input}.{_b64url(sig)}"


def _json(obj: dict) -> bytes:
    return json.dumps(obj, separators=(",", ":"), sort_keys=True).encode("utf-8")


ISS = "https://login.microsoftonline.com/contoso/v2.0"
AUD = "api://vault.acme"


def _payload(**over) -> dict:
    base = {
        "iss": ISS,
        "sub": "agent-7",
        "aud": AUD,
        "exp": 9999999999,
        "cnf": {"jwk": {"kty": "OKP", "crv": "Ed25519", "x": "AAAA"}},
    }
    base.update(over)
    return base


# --------------------------------------------------------------------------- #
# Happy paths                                                                  #
# --------------------------------------------------------------------------- #


def test_rs256_card_from_local_key_verifies():
    signer = RsaSigner()
    src = JwksIdentitySource(
        trusted_issuers={ISS},
        key_provider=StaticJwksProvider({ISS: [signer.jwk]}),
        audiences={AUD},
    )
    res = src.verify_subject_assertion(signer.sign_jwt(_payload()), now=1000.0)
    assert res.verified is True
    assert res.agent_id == "agent-7"
    assert res.issuer == ISS
    assert res.cnf_jwk == {"kty": "OKP", "crv": "Ed25519", "x": "AAAA"}
    assert res.method == "jwks_jwt"


def test_eddsa_card_from_local_key_verifies():
    signer = EddsaSigner()
    src = JwksIdentitySource(
        trusted_issuers={ISS},
        key_provider=StaticJwksProvider({ISS: [signer.jwk]}),
        audiences={AUD},
    )
    res = src.verify_subject_assertion(signer.sign_jwt(_payload()), now=1000.0)
    assert res.verified is True
    assert res.agent_id == "agent-7"


# --------------------------------------------------------------------------- #
# Fail-closed paths                                                           #
# --------------------------------------------------------------------------- #


def test_unknown_issuer_rejected_even_with_valid_signature():
    signer = RsaSigner()
    # The token is genuinely signed, but its iss is not in the trust set.
    src = JwksIdentitySource(
        trusted_issuers={"https://other.example"},
        key_provider=StaticJwksProvider({ISS: [signer.jwk]}),
        audiences={AUD},
    )
    res = src.verify_subject_assertion(signer.sign_jwt(_payload()), now=1000.0)
    assert res.verified is False
    assert res.status == "untrusted_issuer"


def test_wrong_key_rejected():
    signer = RsaSigner()
    other = RsaSigner(kid="rsa-1")  # same kid, different key material
    src = JwksIdentitySource(
        trusted_issuers={ISS},
        key_provider=StaticJwksProvider({ISS: [other.jwk]}),
        audiences={AUD},
    )
    res = src.verify_subject_assertion(signer.sign_jwt(_payload()), now=1000.0)
    assert res.verified is False
    assert res.status == "bad_signature"


def test_tampered_payload_rejected():
    signer = RsaSigner()
    src = JwksIdentitySource(
        trusted_issuers={ISS},
        key_provider=StaticJwksProvider({ISS: [signer.jwk]}),
        audiences={AUD},
    )
    token = signer.sign_jwt(_payload())
    header_b64, _payload_b64, sig_b64 = token.split(".")
    forged = _b64url(_json(_payload(sub="agent-admin")))
    tampered = f"{header_b64}.{forged}.{sig_b64}"
    res = src.verify_subject_assertion(tampered, now=1000.0)
    assert res.verified is False
    assert res.status == "bad_signature"


def test_alg_none_rejected():
    signer = RsaSigner()
    header = {"alg": "none", "kid": signer.kid, "typ": "JWT"}
    body = f"{_b64url(_json(header))}.{_b64url(_json(_payload()))}."
    src = JwksIdentitySource(
        trusted_issuers={ISS},
        key_provider=StaticJwksProvider({ISS: [signer.jwk]}),
        audiences={AUD},
    )
    res = src.verify_subject_assertion(body, now=1000.0)
    assert res.verified is False
    assert res.status == "alg_not_allowed"


def test_audience_mismatch_rejected():
    signer = RsaSigner()
    src = JwksIdentitySource(
        trusted_issuers={ISS},
        key_provider=StaticJwksProvider({ISS: [signer.jwk]}),
        audiences={AUD},
    )
    res = src.verify_subject_assertion(
        signer.sign_jwt(_payload(aud="api://someone-else")), now=1000.0
    )
    assert res.verified is False
    assert res.status == "audience_mismatch"


def test_audience_unconfigured_fails_closed():
    # No configured audiences AND no per-call expected_audience => a validly-signed
    # token with no audience constraint is UNBOUNDED, so it must be REFUSED by
    # default (require_audience=True). The opt-out allows a deliberate no-aud mode.
    signer = RsaSigner()
    no_aud = _payload()
    del no_aud["aud"]
    token = signer.sign_jwt(no_aud)
    src = JwksIdentitySource(
        trusted_issuers={ISS},
        key_provider=StaticJwksProvider({ISS: [signer.jwk]}),
    )  # audiences=None, require_audience defaults True
    res = src.verify_subject_assertion(token, now=1000.0)
    assert res.verified is False
    assert res.status == "audience_unconfigured"
    # Explicit opt-out (e.g. SPIFFE JWT-SVID with no aud) is allowed deliberately.
    src_optout = JwksIdentitySource(
        trusted_issuers={ISS},
        key_provider=StaticJwksProvider({ISS: [signer.jwk]}),
        require_audience=False,
    )
    assert src_optout.verify_subject_assertion(token, now=1000.0).verified is True


def test_expired_rejected():
    signer = RsaSigner()
    src = JwksIdentitySource(
        trusted_issuers={ISS},
        key_provider=StaticJwksProvider({ISS: [signer.jwk]}),
        audiences={AUD},
        leeway=0,
    )
    res = src.verify_subject_assertion(signer.sign_jwt(_payload(exp=500)), now=1000.0)
    assert res.verified is False
    assert res.status == "expired"


def test_unknown_kid_rejected():
    signer = RsaSigner()
    src = JwksIdentitySource(
        trusted_issuers={ISS},
        key_provider=StaticJwksProvider({ISS: [signer.jwk]}),
        audiences={AUD},
    )
    res = src.verify_subject_assertion(
        signer.sign_jwt(_payload(), kid="rotated-out"), now=1000.0
    )
    assert res.verified is False
    assert res.status == "no_matching_key"


def test_no_provider_keys_fails_closed():
    signer = RsaSigner()
    # Default provider has NO keys -> nothing can verify.
    src = JwksIdentitySource(trusted_issuers={ISS}, audiences={AUD})
    res = src.verify_subject_assertion(signer.sign_jwt(_payload()), now=1000.0)
    assert res.verified is False
    assert res.status == "no_matching_key"


def test_malformed_assertion_rejected():
    src = JwksIdentitySource(trusted_issuers={ISS})
    assert src.verify_subject_assertion("not-a-jwt").status == "malformed_jwt"
    assert src.verify_subject_assertion({"x": 1}).status == "malformed_jwt"
