"""B3 — "Demand-Or-Deny + Intent-Bind" named-property test + import-purity test.

The resource-side verifier ``tex.pep.resource.verify.verify_tgpcc`` is a PURE,
AIR-GAPPED function over (presented TG-PCC token, the PRESENTED call, the
holder's DPoP proof, a PINNED local JWKS). It DEMANDS a Tex artifact and
re-binds intent + holder + provenance-floor OFFLINE.

NAMED PROPERTY — Demand-Or-Deny + Intent-Bind. Pass ⇔ all three DENY:
  (1) a resource call with NO TG-PCC                       -> DENY (missing = denial)
  (2) a valid TG-PCC but request params altered after mint -> DENY at intent_commit
  (3) a valid TG-PCC presented by a holder whose DPoP key != cnf.jkt -> DENY
PLUS a happy path:
  (4) a properly-minted TG-PCC + matching request + matching holder -> PERMIT

PLUS an import-graph PURITY test: importing ``tex.pep.resource.verify`` in a
clean subprocess does NOT load the Tex app / PDP / governance / camel / fastapi
/ starlette / numpy / scipy or any network client.

HONESTY (mirrors the module docstring): this is DEMAND-VERIFICATION at an in-path
resource, NOT un-bypassable enforcement; the verifier shape is PARITY; the one
beyond-frontier leg (the prov_commit floor re-check) inherits its novelty from
the taint-gated MINT (B1+). B3 writes no new crypto — these tests mint REAL
broker tokens and verify them through the ported resource-side path.

Targeted run only:
  PYTHONPATH=src .venv/bin/python -m pytest \
    tests/pep/test_resource_verify.py tests/authority -q
"""

from __future__ import annotations

import base64
import json
import os
import subprocess
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from tex.authority import pop
from tex.authority.broker import (
    CredentialBroker,
    canonical_intent_commit,
    tgpcc_public_jwks,
)
from tex.authority.taint_label import PROV_COMMIT_ENC
from tex.camel.capability import (
    CapabilityLevel,
    ConfidentialityLevel,
    FidesLabel,
)
from tex.authority.taint_label import ProvenanceCommitment
from tex.identity.agent_credential import AttestedIdentity
from tex.pep.resource.verify import PresentedRequest, verify_tgpcc

_REPO_ROOT = Path(__file__).resolve().parents[2]
_SRC = _REPO_ROOT / "src"

_AUD = "vault.acme"
_ACT = "read"
_PARAMS = {"to": _AUD, "subject": "ok"}


# --------------------------------------------------------------------------- #
# Helpers (self-contained; no conftest exists in tests/pep)                    #
# --------------------------------------------------------------------------- #


def _pin_ed25519_key(monkeypatch) -> Ed25519PrivateKey:
    """Pin a stable Ed25519 signing key via env so mint signs asymmetrically and
    tgpcc_public_jwks() resolves the SAME key. Turns the TG-PCC plane on.
    (Copied verbatim from tests/authority/test_tgpcc_airgap.py.)"""
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


def _trusted_prov_commit() -> dict:
    """A TRUSTED label dominating a TRUSTED floor (label ⊒ floor) — the floor the
    happy path clears. The producer signs this at mint; here we build the
    committed dict directly for a fast-path broker.mint."""
    commit = ProvenanceCommitment(
        label=FidesLabel(
            integrity=CapabilityLevel.TRUSTED,
            confidentiality=ConfidentialityLevel.PUBLIC,
        ),
        floor=FidesLabel(
            integrity=CapabilityLevel.TRUSTED,
            confidentiality=ConfidentialityLevel.PUBLIC,
        ),
        lineage_root="user-task-root",
        label_id="user-task",
        aud=_AUD,
        act=_ACT,
    )
    return commit.to_prov_commit()


def _mint(monkeypatch, *, holder: Ed25519PrivateKey, params=None, epoch: int = 5):
    """Mint a REAL Ed25519 TG-PCC bound to ``holder`` with a TRUSTED prov_commit
    and an intent_commit over ``params``. Returns the MintedCredential."""
    _pin_ed25519_key(monkeypatch)  # turn the asymmetric plane on before minting
    monkeypatch.setenv("TEX_APP_ENV", "test")
    p = _PARAMS if params is None else params
    broker_ = CredentialBroker(issuer="tex-authority", allow_bearer=True)
    minted = broker_.mint(
        _attested(),
        audience=_AUD,
        action=_ACT,
        scope=["act:read"],
        ttl=300,
        cnf_public_key=holder.public_key(),
        sign_alg="ed25519",
        epoch=epoch,
        intent_commit=canonical_intent_commit(_ACT, _AUD, p),
        prov_commit=_trusted_prov_commit(),
    )
    assert minted is not None
    assert minted.claims.get("alg") == "EdDSA"
    assert minted.claims["prov_commit"]["enc"] == PROV_COMMIT_ENC
    return minted


def _dpop_use_proof(holder: Ed25519PrivateKey, token: str, now: float) -> str:
    """The holder's resource-USE DPoP proof, bound to THIS token (mirrors what a
    real presenter signs; bind == broker._use_binding(token))."""
    import hashlib

    bind = "tex-pop-use:" + hashlib.sha256(token.encode("utf-8")).hexdigest()
    return pop.make_pop_proof(holder, bind=bind, now=now)


# --------------------------------------------------------------------------- #
# Demand-Or-Deny + Intent-Bind — the named property (3 DENY)                   #
# --------------------------------------------------------------------------- #


def test_no_artifact_denies_not_bypass(monkeypatch):
    """(1) A resource call with NO TG-PCC -> DENY. Missing credential is a
    denial, NEVER a bypass."""
    _pin_ed25519_key(monkeypatch)
    jwks = tgpcc_public_jwks()
    req = PresentedRequest(_ACT, _AUD, _PARAMS)

    for missing in (None, "", {}, {"token": ""}):
        chk = verify_tgpcc(missing, req, None, jwks, 0)
        assert chk.ok is False
        assert chk.reason == "no artifact", missing


def test_altered_params_denies_at_intent_commit(monkeypatch):
    """(2) A valid TG-PCC, but the presented params are altered after mint ->
    DENY at intent_commit (confused-deputy / altered-params defense)."""
    holder = Ed25519PrivateKey.generate()
    minted = _mint(monkeypatch, holder=holder)
    jwks = tgpcc_public_jwks()
    now = minted.claims["iat"]
    proof = _dpop_use_proof(holder, minted.token, now)

    # The presenter tries to redirect the action to an attacker recipient.
    tampered = PresentedRequest(_ACT, _AUD, {"to": "attacker.example", "subject": "ok"})
    chk = verify_tgpcc(minted.token, tampered, proof, jwks, 0, now=now)
    assert chk.ok is False
    assert chk.reason == "intent mismatch"


def test_wrong_holder_key_denies(monkeypatch):
    """(3) A valid TG-PCC presented by a holder whose DPoP key != cnf.jkt ->
    DENY (stolen-token defense). The token is bound to ``holder``; a DIFFERENT
    key ``thief`` presents a proof under ITS own key."""
    holder = Ed25519PrivateKey.generate()
    thief = Ed25519PrivateKey.generate()
    minted = _mint(monkeypatch, holder=holder)
    jwks = tgpcc_public_jwks()
    now = minted.claims["iat"]
    req = PresentedRequest(_ACT, _AUD, _PARAMS)

    # Thief signs a use-proof under its own (wrong) key, correctly bound to the
    # token — only the thumbprint differs.
    thief_proof = _dpop_use_proof(thief, minted.token, now)
    chk = verify_tgpcc(minted.token, req, thief_proof, jwks, 0, now=now)
    assert chk.ok is False
    assert chk.reason == "pop: cnf thumbprint mismatch"

    # A sender-constrained token with NO proof at all also denies (no downgrade).
    chk_none = verify_tgpcc(minted.token, req, None, jwks, 0, now=now)
    assert chk_none.ok is False
    assert chk_none.reason == "pop proof required"


# --------------------------------------------------------------------------- #
# Happy path — properly-minted TG-PCC + matching request + holder -> PERMIT    #
# --------------------------------------------------------------------------- #


def test_happy_path_permits(monkeypatch):
    """(4) A properly-minted TG-PCC, presented with the SAME call by the SAME
    holder, over a pinned JWKS, clears all 7 legs -> PERMIT."""
    holder = Ed25519PrivateKey.generate()
    minted = _mint(monkeypatch, holder=holder, epoch=5)
    jwks = tgpcc_public_jwks()
    assert jwks["keys"], "published JWKS must carry the signing key"
    now = minted.claims["iat"]
    req = PresentedRequest(_ACT, _AUD, _PARAMS)
    proof = _dpop_use_proof(holder, minted.token, now)

    chk = verify_tgpcc(
        minted.token,
        req,
        proof,
        jwks,
        5,  # pinned_epoch == token epoch (anti-rollback, not anti-equal)
        expected_issuer="tex-authority",
        now=now,
    )
    assert chk.ok is True, chk.reason
    assert chk.reason == "ok"
    assert chk.claims["prov_commit"]["label"]["integrity"] == int(CapabilityLevel.TRUSTED)
    assert chk.jti  # holder proof jti surfaced for replay-dedupe


def test_artifact_can_be_minted_credential_object(monkeypatch):
    """The demand step accepts the MintedCredential object directly (resource
    presents whatever it received) — _extract_token pulls .token."""
    holder = Ed25519PrivateKey.generate()
    minted = _mint(monkeypatch, holder=holder)
    jwks = tgpcc_public_jwks()
    now = minted.claims["iat"]
    req = PresentedRequest(_ACT, _AUD, _PARAMS)
    proof = _dpop_use_proof(holder, minted.token, now)

    chk = verify_tgpcc(minted, req, proof, jwks, 0, now=now)
    assert chk.ok is True, chk.reason


def test_missing_prov_commit_denies_under_default_posture(monkeypatch):
    """A token with NO prov_commit DENIES under the default-deny posture (the
    inherited-from-B1+ floor leg). Mint without prov_commit then demand it."""
    monkeypatch.setenv("TEX_APP_ENV", "test")
    _pin_ed25519_key(monkeypatch)
    holder = Ed25519PrivateKey.generate()
    broker_ = CredentialBroker(issuer="tex-authority", allow_bearer=True)
    minted = broker_.mint(
        _attested(),
        audience=_AUD,
        action=_ACT,
        scope=["act:read"],
        ttl=300,
        cnf_public_key=holder.public_key(),
        sign_alg="ed25519",
        epoch=5,
        intent_commit=canonical_intent_commit(_ACT, _AUD, _PARAMS),
        # NO prov_commit
    )
    assert minted is not None
    jwks = tgpcc_public_jwks()
    now = minted.claims["iat"]
    req = PresentedRequest(_ACT, _AUD, _PARAMS)
    proof = _dpop_use_proof(holder, minted.token, now)

    chk = verify_tgpcc(minted.token, req, proof, jwks, 0, now=now)
    assert chk.ok is False
    assert chk.reason == "no prov_commit"

    # With the floor not required (a non-taint-gated posture), the SAME token
    # PERMITs — proving the floor is the discriminating leg, not the signature.
    chk_off = verify_tgpcc(
        minted.token, req, proof, jwks, 0, now=now, require_prov_commit=False
    )
    assert chk_off.ok is True, chk_off.reason


def test_default_off_plane_denies(monkeypatch):
    """DEFAULT-OFF inertness: with TEX_TGPCC unset the published JWKS is empty,
    so any token DENIES 'no matching key' (fail-closed), and ed25519 mint is
    None — the verifier is dark by default, not active."""
    monkeypatch.delenv("TEX_TGPCC", raising=False)
    monkeypatch.delenv("TEX_TGPCC_ED25519_SK", raising=False)
    assert tgpcc_public_jwks() == {"keys": []}

    # A previously-minted token (any string) verified against the empty pinned
    # JWKS denies — no key resolves.
    req = PresentedRequest(_ACT, _AUD, _PARAMS)
    dummy = base64.urlsafe_b64encode(
        json.dumps({"alg": "EdDSA"}).encode()
    ).rstrip(b"=").decode() + ".sig"
    chk = verify_tgpcc(dummy, req, None, {"keys": []}, 0)
    assert chk.ok is False
    assert chk.reason == "no matching key"


# --------------------------------------------------------------------------- #
# IMPORT-GRAPH PURITY — the Tex app/PDP/heavy runtime must NOT load            #
# --------------------------------------------------------------------------- #


def test_resource_verify_import_is_pure():
    """Importing tex.pep.resource.verify in a CLEAN subprocess loads NONE of the
    Tex app / PDP / governance / camel / fastapi / starlette / numpy / scipy, and
    NO network client. This is what lets a downstream resource pull the verifier
    in without dragging the whole runtime — the load-bearing B3 property."""
    code = (
        "import sys\n"
        "import tex.pep.resource.verify  # the demand-side verifier\n"
        "heavy_prefixes = ('tex.governance','tex.camel','tex.api','tex.main',\n"
        "    'tex.engine','tex.enforcement','tex.authority','tex.systemic',\n"
        "    'tex.proxy','fastapi','starlette','uvicorn','numpy','scipy')\n"
        "leaked_heavy = sorted(m for m in sys.modules\n"
        "    if any(m == p or m.startswith(p + '.') for p in heavy_prefixes))\n"
        "net = sorted(m for m in sys.modules\n"
        "    if m.split('.')[0] in {'requests','httpx','aiohttp','urllib3'})\n"
        "import json\n"
        "print(json.dumps({'heavy': leaked_heavy, 'net': net}))\n"
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
    assert got["heavy"] == [], f"verify import leaked heavy modules: {got['heavy']}"
    assert got["net"] == [], f"verify import leaked a network client: {got['net']}"


def test_resource_middleware_import_is_pure():
    """The middleware module is ALSO importable purely (it wraps the pure
    verifier and adds only stdlib ASGI plumbing) — so __init__.py exporting it
    does not re-contaminate the package."""
    code = (
        "import sys\n"
        "import tex.pep.resource.middleware\n"
        "heavy_prefixes = ('tex.governance','tex.camel','tex.api','tex.main',\n"
        "    'tex.engine','tex.enforcement','tex.authority','tex.systemic',\n"
        "    'tex.proxy','fastapi','starlette','uvicorn','numpy','scipy')\n"
        "leaked = sorted(m for m in sys.modules\n"
        "    if any(m == p or m.startswith(p + '.') for p in heavy_prefixes))\n"
        "import json\n"
        "print(json.dumps(leaked))\n"
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
    leaked = json.loads(out.stdout.strip().splitlines()[-1])
    assert leaked == [], f"middleware import leaked heavy modules: {leaked}"


# --------------------------------------------------------------------------- #
# Byte-parity with the broker primitives (B3 reinvents no crypto)             #
# --------------------------------------------------------------------------- #


def test_canonical_intent_commit_matches_broker():
    """The ported canonical_intent_commit is byte-for-byte identical to the
    broker's (so the recomputed commitment matches the minted one)."""
    from tex.pep.resource.verify import canonical_intent_commit as ported

    for params in ({"a": 1, "b": 2}, {"b": 2, "a": 1}, {}, {"to": _AUD}):
        assert ported(_ACT, _AUD, params) == canonical_intent_commit(_ACT, _AUD, params)
