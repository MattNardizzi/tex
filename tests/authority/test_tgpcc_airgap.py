"""Step 0 + B2 tests — the TG-PCC claim schema, its byte-stable canonical
serializer, and the Air-Gap-Verify property of the Ed25519 (asymmetric) leg.

HONESTY (do not relabel): B2 is PARITY plumbing. An offline, public-key verify
of an attenuable capability token is the DEPLOYED shape (AIP / Biscuit /
Vouchsafe) — table-stakes, necessary, fail-closed, and NOT a novel mechanism.
Its only worth is carrying a future provenance commitment across a trust
boundary so a remote verifier can check Tex's signature with no shared secret
and no network call. These tests pin exactly that:

  * STEP 0 — a TG-PCC round-trips mint(claims) -> serialize -> deserialize, and
    its canonical ``(method, resource, params)`` commitment + body bytes are
    byte-IDENTICAL across two separate Python processes (golden-vector).
  * B2 "Air-Gap-Verify" — a PURE verify function over a PINNED LOCAL JWKS dict
    (provably no network: an import-scan in a clean subprocess + a socket guard)
    yields: (a) valid -> PERMIT/ok; (b) non-published key -> DENY; (c) epoch
    below the PEP's pinned epoch -> DENY.
  * DEFAULT-OFF inertness — with ``TEX_TGPCC`` unset the asymmetric path is
    inert (no key resolves, the JWKS is empty, the HMAC leg is unchanged).
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import socket
import subprocess
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from tex.authority import broker
from tex.authority.broker import (
    CredentialBroker,
    TgPccClaims,
    authority_ed25519_key,
    canonical_act,
    canonical_intent_commit,
    tgpcc_public_jwks,
    verify_with_jwks,
)
from tex.identity.agent_credential import AttestedIdentity

_REPO_ROOT = Path(__file__).resolve().parents[2]
_SRC = _REPO_ROOT / "src"


# --------------------------------------------------------------------------- #
# Helpers                                                                      #
# --------------------------------------------------------------------------- #


def _pin_ed25519_key(monkeypatch) -> Ed25519PrivateKey:
    """Pin a STABLE Ed25519 signing key via env (b64url raw seed) so mint and
    the published JWKS resolve the SAME key across calls. Turns the TG-PCC plane
    on. Returns the private key for direct use in tests."""
    sk = Ed25519PrivateKey.generate()
    seed = sk.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    monkeypatch.setenv("TEX_TGPCC", "1")
    monkeypatch.setenv(
        "TEX_TGPCC_ED25519_SK",
        base64.urlsafe_b64encode(seed).rstrip(b"=").decode("ascii"),
    )
    return sk


def _attested() -> AttestedIdentity:
    return AttestedIdentity(
        verified=True,
        status="ok",
        issuer="entra://contoso",
        claimed_agent_id="agent-7",
    )


def _other_key_jwks() -> dict:
    """A JWKS holding a DIFFERENT Ed25519 key than the one that signs — the
    'non-published key' case (b)."""
    other = Ed25519PrivateKey.generate()
    raw = broker.pop.raw_public_bytes(other.public_key())
    jwk = broker.pop.public_jwk(raw)
    kid = broker.pop.jwk_thumbprint(jwk)
    return {"keys": [{**jwk, "kid": kid, "use": "sig", "alg": "EdDSA"}]}


# --------------------------------------------------------------------------- #
# STEP 0 — TG-PCC claim schema + canonical byte-stability                      #
# --------------------------------------------------------------------------- #

# A fixed TG-PCC claim set (keys deliberately constructed out of declaration
# order; prov_commit=None is the Step-0 placeholder slot). Captured ONCE and
# frozen here — any accidental change to the canonical serializer in a future
# edit flips these constants and fails the test.
_GOLDEN_DECODED = (
    '{"act":{"method":"read","resource":"urn:res:doc/42"},'
    '"aud":"vault.acme","cnf":{"jkt":"AAAAtest_thumbprint"},'
    '"epoch":7,"exp":1010,'
    '"intent_commit":"c81baf0e33f1383121be9f48007d4ba848ced09424bdd728b344d9b63dc9ec4a",'
    '"iss":"tex-authority","nbf":1000,'
    '"scp":["act:read","act:read@vault.acme"],"sub":"agent-7"}'
)
_GOLDEN_HEX = "e4bef00c20be540be95a2df3402e8eacacaf1e4d2f43162b754e14f36699f951"


def _golden_claims() -> TgPccClaims:
    return TgPccClaims(
        iss="tex-authority",
        sub="agent-7",
        aud="vault.acme",
        act=canonical_act("read", "urn:res:doc/42"),
        scp=("act:read", "act:read@vault.acme"),
        cnf={"jkt": "AAAAtest_thumbprint"},
        intent_commit=canonical_intent_commit("read", "urn:res:doc/42", {"b": 2, "a": 1}),
        exp=1010,
        nbf=1000,
        epoch=7,
        prov_commit=None,  # Step-0 placeholder; populated by B1+ later
    )


def test_tgpcc_roundtrips():
    """A TG-PCC round-trips through serialize -> deserialize with no loss, and
    the prov_commit slot is carried as None (placeholder this step)."""
    tg = _golden_claims()
    body = tg.serialize()
    back = TgPccClaims.deserialize(body)
    assert back.iss == "tex-authority"
    assert back.sub == "agent-7"
    assert back.aud == "vault.acme"
    assert back.act == {"method": "read", "resource": "urn:res:doc/42"}
    assert back.scp == ("act:read", "act:read@vault.acme")
    assert back.cnf == {"jkt": "AAAAtest_thumbprint"}
    assert back.intent_commit == tg.intent_commit
    assert back.exp == 1010 and back.nbf == 1000 and back.epoch == 7
    assert back.prov_commit is None  # slot present, empty this step


def test_prov_commit_slot_is_carried_when_present():
    """When B1+ populates prov_commit, the slot serializes + round-trips."""
    prov = {
        "label": {"integrity": "high", "confidentiality": "secret"},
        "floor": "permit",
        "lineage_root": "abc123",
        "label_id": "lbl-7",
    }
    tg = TgPccClaims(
        iss="tex-authority",
        sub="agent-7",
        aud="vault.acme",
        act=canonical_act("read", "res"),
        scp=("act:read",),
        cnf=None,
        intent_commit=canonical_intent_commit("read", "res", {}),
        exp=10,
        nbf=0,
        epoch=1,
        prov_commit=prov,
    )
    back = TgPccClaims.deserialize(tg.serialize())
    assert back.prov_commit == prov


def test_intent_commit_is_deterministic_and_order_insensitive():
    """The intent commitment is a stable SHA-256 over canonical (method,
    resource, params) — independent of params key order."""
    a = canonical_intent_commit("read", "res", {"a": 1, "b": 2})
    b = canonical_intent_commit("read", "res", {"b": 2, "a": 1})
    assert a == b
    assert len(a) == 64 and all(c in "0123456789abcdef" for c in a)
    # a different action commits to a different hash
    assert canonical_intent_commit("write", "res", {"a": 1, "b": 2}) != a


def test_canonical_bytes_stable_across_process():
    """GOLDEN-VECTOR: the canonical TG-PCC body bytes (the bytes a signature
    covers) are byte-IDENTICAL when produced in a SEPARATE Python process. This
    is what makes a signed capability verifiable cross-host."""
    code = (
        "import json, hashlib\n"
        "from tex.authority.broker import (TgPccClaims, canonical_act,\n"
        "    canonical_intent_commit)\n"
        "from tex.enforcement.permit import _b64url_decode\n"
        "tg = TgPccClaims(iss='tex-authority', sub='agent-7', aud='vault.acme',\n"
        "    act=canonical_act('read','urn:res:doc/42'),\n"
        "    scp=('act:read','act:read@vault.acme'),\n"
        "    cnf={'jkt':'AAAAtest_thumbprint'},\n"
        "    intent_commit=canonical_intent_commit('read','urn:res:doc/42',{'b':2,'a':1}),\n"
        "    exp=1010, nbf=1000, epoch=7, prov_commit=None)\n"
        "body = tg.serialize()\n"
        "raw = _b64url_decode(body).decode('utf-8')\n"
        "print(json.dumps({'hex': hashlib.sha256(body.encode('utf-8')).hexdigest(),\n"
        "    'raw': raw}))\n"
    )
    env = dict(os.environ, PYTHONPATH=str(_SRC))
    out = subprocess.run(
        [sys.executable, "-c", code],
        capture_output=True,
        text=True,
        env=env,
        cwd=str(_REPO_ROOT),
    )
    assert out.returncode == 0, out.stderr
    got = json.loads(out.stdout.strip().splitlines()[-1])

    # 1) cross-process == in-process (determinism across interpreters)
    in_proc = _golden_claims().serialize()
    assert got["hex"] == hashlib.sha256(in_proc.encode("utf-8")).hexdigest()
    # 2) frozen golden — catches an accidental serializer change anywhere
    assert got["hex"] == _GOLDEN_HEX
    # 3) the raw bytes are exactly sort-keys + compact (no spaces, sorted keys)
    assert got["raw"] == _GOLDEN_DECODED


# --------------------------------------------------------------------------- #
# B2 — AIR-GAP-VERIFY: provably ZERO network                                   #
# --------------------------------------------------------------------------- #


def test_verify_module_imports_no_network_client():
    """STRUCTURAL air-gap proof: importing the verify module in a CLEAN
    subprocess pulls in NONE of the third-party network clients. The verify
    path is a pure function over (token, jwks) — it constructs no HTTP client."""
    code = (
        "import sys\n"
        "import tex.authority.broker  # the module that holds verify_with_jwks\n"
        "leaked = sorted(m for m in sys.modules\n"
        "    if m.split('.')[0] in {'requests','httpx','aiohttp','urllib3'})\n"
        "print(leaked)\n"
    )
    env = dict(os.environ, PYTHONPATH=str(_SRC))
    out = subprocess.run(
        [sys.executable, "-c", code],
        capture_output=True,
        text=True,
        env=env,
        cwd=str(_REPO_ROOT),
    )
    assert out.returncode == 0, out.stderr
    leaked = json.loads(out.stdout.strip().splitlines()[-1].replace("'", '"'))
    assert leaked == [], f"verify path imported a network client: {leaked}"


def test_airgap_verify_valid_permit(monkeypatch):
    """(a) A valid Ed25519 TG-PCC credential verifies to PERMIT/ok over a PINNED
    in-memory JWKS — with sockets disabled to PROVE no network is touched."""
    sk = _pin_ed25519_key(monkeypatch)
    monkeypatch.setenv("TEX_APP_ENV", "test")

    broker_ = CredentialBroker(issuer="tex-authority", allow_bearer=True)
    holder = Ed25519PrivateKey.generate()
    minted = broker_.mint(
        _attested(),
        audience="vault.acme",
        action="read",
        scope=["act:read"],
        ttl=300,
        cnf_public_key=holder.public_key(),
        sign_alg="ed25519",
        epoch=5,
    )
    assert minted is not None
    assert minted.claims.get("alg") == "EdDSA"
    jwks = tgpcc_public_jwks()
    assert jwks["keys"], "the published JWKS must carry the signing public key"

    # Air-gap guard: any socket construction inside verify fails the test.
    def _boom(*a, **k):
        raise AssertionError("air-gap violated: a socket was opened during verify")

    monkeypatch.setattr(socket, "socket", _boom)

    chk = verify_with_jwks(minted.token, jwks, pinned_epoch=5, now=minted.claims["iat"])
    assert chk.ok is True
    assert chk.reason == "ok"
    # sanity: the verifying key the JWKS carries is exactly the signing key's pub
    raw = sk.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    assert jwks["keys"][0]["x"] == broker.pop.public_jwk(raw)["x"]


def test_airgap_verify_wrong_key_denies(monkeypatch):
    """(b) A token signed by a key that is NOT in the pinned JWKS is DENIED."""
    _pin_ed25519_key(monkeypatch)
    monkeypatch.setenv("TEX_APP_ENV", "test")
    broker_ = CredentialBroker(issuer="tex-authority", allow_bearer=True)
    minted = broker_.mint(
        _attested(),
        audience="vault.acme",
        action="read",
        scope=["act:read"],
        ttl=300,
        sign_alg="ed25519",
        epoch=5,
    )
    assert minted is not None

    # The verifier is handed a JWKS for a DIFFERENT key (same alg/shape). Its
    # kid won't match the token's single-key resolve either way => DENY.
    bad_jwks = _other_key_jwks()
    chk = verify_with_jwks(minted.token, bad_jwks, now=minted.claims["iat"])
    assert chk.ok is False
    assert chk.reason in {"bad signature", "no matching key"}


def test_airgap_verify_stale_epoch_denies(monkeypatch):
    """(c) A token whose epoch is BELOW the PEP's pinned epoch is DENIED."""
    _pin_ed25519_key(monkeypatch)
    monkeypatch.setenv("TEX_APP_ENV", "test")
    broker_ = CredentialBroker(issuer="tex-authority", allow_bearer=True)
    minted = broker_.mint(
        _attested(),
        audience="vault.acme",
        action="read",
        scope=["act:read"],
        ttl=300,
        sign_alg="ed25519",
        epoch=3,  # the token's epoch
    )
    assert minted is not None
    jwks = tgpcc_public_jwks()

    # PEP has rotated forward to epoch 9 — the epoch-3 token is stale.
    chk = verify_with_jwks(minted.token, jwks, pinned_epoch=9, now=minted.claims["iat"])
    assert chk.ok is False
    assert chk.reason == "stale epoch"

    # At the floor (epoch == pinned) it is accepted (anti-rollback, not anti-equal).
    ok = verify_with_jwks(minted.token, jwks, pinned_epoch=3, now=minted.claims["iat"])
    assert ok.ok is True


def test_airgap_verify_expired_denies(monkeypatch):
    """A token past its exp is DENIED offline (fail-closed on expiry)."""
    _pin_ed25519_key(monkeypatch)
    monkeypatch.setenv("TEX_APP_ENV", "test")
    broker_ = CredentialBroker(issuer="tex-authority", allow_bearer=True)
    minted = broker_.mint(
        _attested(),
        audience="vault.acme",
        action="read",
        scope=["act:read"],
        ttl=10,
        sign_alg="ed25519",
        now=1000.0,
    )
    assert minted is not None
    jwks = tgpcc_public_jwks()
    chk = verify_with_jwks(minted.token, jwks, now=100000.0)
    assert chk.ok is False
    assert chk.reason == "expired"


def test_airgap_verify_tampered_body_denies(monkeypatch):
    """Flipping a byte in the signed body invalidates the Ed25519 signature."""
    _pin_ed25519_key(monkeypatch)
    monkeypatch.setenv("TEX_APP_ENV", "test")
    broker_ = CredentialBroker(issuer="tex-authority", allow_bearer=True)
    minted = broker_.mint(
        _attested(),
        audience="vault.acme",
        action="read",
        scope=["act:read"],
        ttl=300,
        sign_alg="ed25519",
        epoch=5,
    )
    assert minted is not None
    jwks = tgpcc_public_jwks()
    body, _, sig = minted.token.partition(".")
    # Decode, mutate a claim, re-encode the body but keep the OLD signature.
    claims = json.loads(broker._b64url_decode(body))
    claims["scope"] = ["act:admin"]  # privilege escalation attempt
    forged_body = broker._canonical(claims)
    forged = f"{forged_body}.{sig}"
    chk = verify_with_jwks(forged, jwks, now=minted.claims["iat"])
    assert chk.ok is False
    assert chk.reason == "bad signature"


# --------------------------------------------------------------------------- #
# DEFAULT-OFF inertness (the asymmetric leg must be dark by default)           #
# --------------------------------------------------------------------------- #


def test_default_off_no_key_no_jwks(monkeypatch):
    """With TEX_TGPCC unset the asymmetric plane is inert: no key resolves and
    the published JWKS is empty. (The HMAC leg is unaffected — proven by the
    existing broker/govern-mint tests staying green.)"""
    monkeypatch.delenv("TEX_TGPCC", raising=False)
    monkeypatch.delenv("TEX_TGPCC_ED25519_SK", raising=False)
    assert authority_ed25519_key() is None
    assert tgpcc_public_jwks() == {"keys": []}


def test_ed25519_requested_but_off_fails_closed(monkeypatch):
    """If ed25519 is explicitly requested while the plane is OFF, mint FAILS
    CLOSED (returns None) — NEVER a silent HMAC downgrade for a token the caller
    believed was asymmetric."""
    monkeypatch.delenv("TEX_TGPCC", raising=False)
    monkeypatch.delenv("TEX_TGPCC_ED25519_SK", raising=False)
    broker_ = CredentialBroker(issuer="tex-authority", allow_bearer=True)
    minted = broker_.mint(
        _attested(),
        audience="vault.acme",
        action="read",
        scope=["act:read"],
        ttl=300,
        sign_alg="ed25519",
    )
    assert minted is None


def test_ed25519_unparseable_key_fails_closed(monkeypatch):
    """A set-but-garbage TEX_TGPCC_ED25519_SK fails closed (no ephemeral
    fallback for an explicitly-configured key)."""
    monkeypatch.setenv("TEX_TGPCC", "1")
    monkeypatch.setenv("TEX_TGPCC_ED25519_SK", "not-a-valid-key")
    assert authority_ed25519_key() is None


def test_prod_unset_key_fails_closed(monkeypatch):
    """Production-like env + flag on + key unset => no ephemeral key in prod."""
    monkeypatch.setenv("TEX_TGPCC", "1")
    monkeypatch.delenv("TEX_TGPCC_ED25519_SK", raising=False)
    monkeypatch.setenv("TEX_APP_ENV", "production")
    assert authority_ed25519_key() is None


def test_hmac_default_unchanged_no_alg_claim(monkeypatch):
    """The default (HMAC) mint writes NO ``alg`` claim — the canonical body is
    byte-for-byte the pre-B2 shape, so B1's token bytes are untouched."""
    monkeypatch.setenv("TEX_AUTHORITY_SIGNING_SECRET", "authority-test-secret")
    monkeypatch.setenv("TEX_APP_ENV", "test")
    broker_ = CredentialBroker(issuer="tex-authority", allow_bearer=True)
    minted = broker_.mint(
        _attested(),
        audience="vault.acme",
        action="read",
        scope=["act:read"],
        ttl=300,
    )
    assert minted is not None
    assert "alg" not in minted.claims
    # And it verifies through the existing HMAC instance path.
    chk = broker_.verify(minted.token, expected_audience="vault.acme", expected_action="read")
    assert chk.ok is True
