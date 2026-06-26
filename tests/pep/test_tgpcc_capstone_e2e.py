"""TG-PCC CAPSTONE — the FIRST time all three legs run in ONE unified flow.

This is the end-to-end integration test that exercises the WHOLE taint-gated
proof-carrying-capability pipeline as a single composed system, not three
isolated units:

    trusted producer stamps an integrity label
        -> POST /v1/govern/mint  (B1 route + B1+ taint gate)
            mints a taint-gated, Ed25519-signed TG-PCC (B2 schema/signing)
            with intent_commit + prov_commit embedded INSIDE the signed body
        -> the downstream RESOURCE demands + verifies it OFFLINE
            via tex.pep.resource.verify_tgpcc over the PINNED JWKS  (B3)

Every leg is the REAL one:
  * the REAL FastAPI route (``build_governance_standing_router``) via TestClient
    is the minter — NOT a hand-built broker.mint;
  * a REAL trusted-producer ``ProvenanceCommitment`` is HMAC-signed with the
    operator secret the calling agent does not hold;
  * a REAL Ed25519 TG-PCC + REAL DPoP holder key are minted;
  * the REAL B3 ``pep.resource.verify_tgpcc`` (the air-gapped, import-pure
    demand-verifier) is the resource.

The four scenarios are the named composite properties:

  1. HAPPY PATH — a TRUSTED operand (derived from the user task) mints a
     taint-gated TG-PCC; the resource PERMITs; AND the verify works with the
     network DOWN (``socket.socket`` raises during the resource verify), proving
     the demand-side check is genuinely air-gapped.
  2. INJECTION-MINTS-NOTHING — the identical action with one UNTRUSTED operand
     gets NO token (403 insufficient_integrity); the resource, handed no
     artifact, DENYs (missing = denial). Injection cannot obtain a credential,
     so the resource never even sees one.
  3. REPLAY — the happy-path token presented to the resource for a DIFFERENT
     request DENYs at intent_commit (the signed intent no longer matches the
     presented call).
  4. TAMPER — flipping the embedded ``prov_commit`` label TRUSTED->UNTRUSTED in
     the signed token DENYs with 'bad signature' (the label is signature-COVERED,
     not advisory — you cannot launder a tainted label after issuance).

HONESTY (do not relabel): this proves the COMPOSED pipeline end-to-end on the
out-of-path issuance + demand-verification plane. It is issuance-gating +
offline demand-verification, NOT un-bypassable in-path enforcement; the verifier
SHAPE is parity; the single beyond-frontier leg is the prov_commit floor, whose
novelty is inherited from the taint-gated mint. The label assessor is in the TCB.

Targeted run only:
  PYTHONPATH=src .venv/bin/python -m pytest \
    tests/pep/test_tgpcc_capstone_e2e.py tests/pep tests/authority tests/governance -q
"""

from __future__ import annotations

import base64
import hashlib
import json
import socket
from uuid import uuid4

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi import FastAPI
from fastapi.testclient import TestClient

from tex.api.auth import TexPrincipal, authenticate_request
from tex.api.governance_standing_routes import build_governance_standing_router
from tex.authority import pop
from tex.authority.broker import canonical_intent_commit, tgpcc_public_jwks
from tex.authority.taint_label import (
    OperandNode,
    ProvenanceCommitment,
    compute_lineage_root,
    meet_label,
    sign_label_envelope,
)
from tex.camel.capability import (
    CapabilityLevel,
    ConfidentialityLevel,
    FidesLabel,
)
from tex.domain.verdict import Verdict
from tex.governance.standing import DecisionOutcome
from tex.pep.resource.verify import PresentedRequest, verify_tgpcc

# Operator-held secrets — the calling agent holds NEITHER.
AUTHORITY_SECRET = "shared-authority-signing-secret"
PRODUCER_SECRET = "operator-held-label-producer-secret"

# The action under test. The intent params derive from the user task.
_AUD = "payroll.example"
_ACT = "send_email"
_PARAMS = {"to": _AUD, "subject": "approved payroll note"}


# --------------------------------------------------------------------------- #
# Harness — the REAL route + a FAKE governance brain (PERMIT, as in B1 tests). #
# The ONLY thing that can refuse a PERMIT here is the taint gate, so a refusal #
# proves the taint leg fired, not the brain.                                   #
# --------------------------------------------------------------------------- #


class _FakeGovernance:
    """Records decide() kwargs and returns a pre-seeded DecisionOutcome."""

    def __init__(self, outcome: DecisionOutcome) -> None:
        self._outcome = outcome
        self.last_kwargs: dict | None = None

    def decide(self, **kwargs) -> DecisionOutcome:
        self.last_kwargs = kwargs
        return self._outcome


def _client(gov: object) -> TestClient:
    app = FastAPI()
    app.include_router(build_governance_standing_router())
    app.state.standing_governance = gov
    app.dependency_overrides[authenticate_request] = lambda: TexPrincipal(
        api_key_fingerprint="test",
        tenant="acme",
        scopes=frozenset({"decision:write"}),
    )
    return TestClient(app)


def _permit_outcome() -> DecisionOutcome:
    return DecisionOutcome(
        verdict=Verdict.PERMIT,
        released=True,
        reason="released by deep adjudication",
        tier="deep",
        decision_id=uuid4(),
        evidence_hash="abc123",
    )


def _full_env(monkeypatch) -> Ed25519PrivateKey:
    """Turn ALL three legs on: govern-mint + taint-gate + TG-PCC asymmetric
    plane, with a PINNED Ed25519 signing key so the published JWKS resolves the
    same key the route signs with. Returns the signing private key."""
    monkeypatch.setenv("TEX_GOVERN_MINT", "1")
    monkeypatch.setenv("TEX_AUTHORITY_SIGNING_SECRET", AUTHORITY_SECRET)
    monkeypatch.setenv("TEX_TAINT_GATED_MINT", "1")
    monkeypatch.setenv("TEX_TAINT_LABEL_SECRET", PRODUCER_SECRET)
    monkeypatch.setenv("TEX_APP_ENV", "test")
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


def _mint_bind_proof(
    holder: Ed25519PrivateKey, *, audience: str, action: str
) -> str:
    """A REAL DPoP/PoP proof bound to the route's MINT context (the route
    verifies ``tex-pop-mint:{jkt}:{aud}:{act}`` — see governance_standing_routes
    section F)."""
    jkt = pop.thumbprint(holder.public_key())
    bind = f"tex-pop-mint:{jkt}:{audience}:{action}"
    return pop.make_pop_proof(holder, bind=bind)


def _use_proof(holder: Ed25519PrivateKey, token: str, now: float) -> str:
    """The holder's resource-USE DPoP proof, bound to THIS token
    (bind == broker._use_binding(token) == 'tex-pop-use:'+sha256(token))."""
    bind = "tex-pop-use:" + hashlib.sha256(token.encode("utf-8")).hexdigest()
    return pop.make_pop_proof(holder, bind=bind, now=now)


def _producer_label_fields(*, nodes, integrity, confidentiality, label_id):
    """The trusted-producer-signed label fields the caller PRESENTS to the route.

    The producer computes the operand meet + a Merkle lineage_root over the
    operand DAG, builds a ProvenanceCommitment against a TRUSTED/PUBLIC floor,
    and HMAC-signs it with PRODUCER_SECRET. The route re-derives the SAME
    commitment from these fields and re-verifies the signature before it mints.
    The intent (method/resource/params) derives from the user task.
    """
    lineage = compute_lineage_root(nodes)
    commit = ProvenanceCommitment(
        label=FidesLabel(integrity=integrity, confidentiality=confidentiality),
        floor=FidesLabel(
            integrity=CapabilityLevel.TRUSTED,
            confidentiality=ConfidentialityLevel.PUBLIC,
        ),
        lineage_root=lineage,
        label_id=label_id,
        aud=_AUD,
        act=_ACT,
    )
    sig = sign_label_envelope(commit, secret=PRODUCER_SECRET)
    return {
        "operand_label_integrity": int(integrity),
        "operand_label_confidentiality": int(confidentiality),
        "operand_label_id": label_id,
        "lineage_root": lineage,
        "label_signature": sig,
        "intent_method": _ACT,
        "intent_resource": _AUD,
        "intent_params": _PARAMS,
    }


def _decode_claims(token: str) -> dict:
    body_b64 = token.partition(".")[0]
    return json.loads(
        base64.urlsafe_b64decode(body_b64 + "=" * (-len(body_b64) % 4))
    )


# --------------------------------------------------------------------------- #
# 1. HAPPY PATH — mint a taint-gated TG-PCC; resource PERMITs AIR-GAPPED.      #
# --------------------------------------------------------------------------- #


def test_capstone_happy_path_permits_airgapped(monkeypatch) -> None:
    """All three legs in one flow: a TRUSTED user-task operand mints a
    taint-gated, Ed25519-signed TG-PCC carrying intent_commit + prov_commit in
    the signed body; the B3 resource verifier PERMITs over the PINNED JWKS WITH
    THE NETWORK DOWN."""
    sk = _full_env(monkeypatch)

    # LEG 1 (producer): a trusted-only operand DAG derived from the user task.
    nodes = [
        OperandNode(
            "u1", "user-task", CapabilityLevel.TRUSTED, ConfidentialityLevel.PUBLIC
        ),
    ]
    assert meet_label(nodes).integrity == CapabilityLevel.TRUSTED  # dominates floor
    label_fields = _producer_label_fields(
        nodes=nodes,
        integrity=CapabilityLevel.TRUSTED,
        confidentiality=ConfidentialityLevel.PUBLIC,
        label_id="user-task",
    )

    # LEG 2 (route mint): real Ed25519 TG-PCC + real DPoP holder key.
    holder = Ed25519PrivateKey.generate()
    proof = _mint_bind_proof(holder, audience=_AUD, action=_ACT)
    resp = _client(_FakeGovernance(_permit_outcome())).post(
        "/v1/govern/mint",
        json={
            "action_type": _ACT,
            "content": "send the approved payroll note",
            "recipient": _AUD,
            "dpop_proof": proof,
            "ttl": 120,
            **label_fields,
        },
    )
    assert resp.status_code == 200, resp.text
    payload = resp.json()
    token = payload["access_token"]
    assert token
    jkt = pop.thumbprint(holder.public_key())
    assert payload["cnf"]["jkt"] == jkt

    # The token is Ed25519-signed (TG-PCC plane on) and carries the SIGNED
    # intent_commit + prov_commit INSIDE the signed body.
    claims = _decode_claims(token)
    assert claims["alg"] == "EdDSA"
    assert claims["intent_commit"] == canonical_intent_commit(_ACT, _AUD, _PARAMS)
    assert claims["prov_commit"]["label"]["integrity"] == int(CapabilityLevel.TRUSTED)
    assert claims["prov_commit"]["floor"]["integrity"] == int(CapabilityLevel.TRUSTED)

    # LEG 3 (resource): pin the published JWKS, build the holder USE-proof, and
    # demand-verify the token OFFLINE for the SAME call by the SAME holder.
    jwks = tgpcc_public_jwks()
    assert jwks["keys"], "published JWKS must carry the signing key"
    now = claims["iat"]
    req = PresentedRequest(_ACT, _AUD, _PARAMS)
    use_proof = _use_proof(holder, token, now)

    # AIR-GAP: any socket construction during the resource verify FAILS the test.
    def _boom(*a, **k):
        raise AssertionError(
            "air-gap violated: a socket was opened during resource verify"
        )

    monkeypatch.setattr(socket, "socket", _boom)

    # pinned_epoch=None: the REAL /v1/govern/mint route mints WITHOUT an ``epoch``
    # claim (it never passes ``epoch`` into broker.mint — see
    # governance_standing_routes section I), so a resource MUST NOT pin an epoch
    # for route-minted tokens or every one DENYs 'missing epoch'. This is the
    # honest cross-leg integration contract: route-minted TG-PCCs are epoch-less;
    # the anti-rollback epoch floor is a broker-direct mint feature only.
    chk = verify_tgpcc(
        token,
        req,
        use_proof,
        jwks,
        pinned_epoch=None,
        expected_issuer="tex-authority",
        now=now,
    )
    assert chk.ok is True, chk.reason
    assert chk.reason == "ok"
    # Confirm the route-minted token genuinely carries no epoch claim (the reason
    # a pinned epoch would wrongly deny it).
    assert "epoch" not in claims
    # The resource re-checked label ⊒ floor offline from the SIGNED claims.
    assert chk.claims["prov_commit"]["label"]["integrity"] == int(
        CapabilityLevel.TRUSTED
    )
    assert chk.jti  # holder-proof jti surfaced for replay-dedupe

    # Sanity: the verifying JWKS key is the route's signing key's public half.
    raw = sk.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    assert jwks["keys"][0]["x"] == pop.public_jwk(raw)["x"]


# --------------------------------------------------------------------------- #
# 2. INJECTION-MINTS-NOTHING — untrusted operand => no token => resource DENYs #
# --------------------------------------------------------------------------- #


def test_capstone_injection_mints_nothing_resource_denies(monkeypatch) -> None:
    """The IDENTICAL action with one UNTRUSTED operand obtains NO token (403
    insufficient_integrity), and the resource — handed no artifact — DENYs
    (missing = denial). Injection cannot acquire a credential, so it never
    reaches the resource with one."""
    _full_env(monkeypatch)

    # LEG 1 (producer): one operand derives from quarantined/untrusted data ->
    # the meet floors to UNTRUSTED, under the TRUSTED floor.
    nodes = [
        OperandNode(
            "u1", "user-task", CapabilityLevel.TRUSTED, ConfidentialityLevel.PUBLIC
        ),
        OperandNode(
            "e1",
            "email_body",
            CapabilityLevel.UNTRUSTED,
            ConfidentialityLevel.CONFIDENTIAL,
        ),
    ]
    meet = meet_label(nodes)
    assert meet.integrity == CapabilityLevel.UNTRUSTED  # the injection floors it
    label_fields = _producer_label_fields(
        nodes=nodes,
        integrity=meet.integrity,
        confidentiality=meet.confidentiality,
        label_id="email_body",
    )

    holder = Ed25519PrivateKey.generate()
    proof = _mint_bind_proof(holder, audience=_AUD, action=_ACT)
    resp = _client(_FakeGovernance(_permit_outcome())).post(
        "/v1/govern/mint",
        json={
            "action_type": _ACT,
            "content": "send the approved payroll note",
            "recipient": _AUD,
            "dpop_proof": proof,
            **label_fields,
        },
    )
    # Refuse-before-sign: 403, NO token, reason = insufficient_integrity.
    assert resp.status_code == 403, resp.text
    payload = resp.json()
    assert payload["released"] is False
    assert "access_token" not in payload
    assert "token" not in payload
    assert payload["reason"].startswith("insufficient_integrity")

    # LEG 3 (resource): the agent has NO artifact to present. The default-DENY
    # resource verifier treats a missing token as a denial, never a bypass.
    jwks = tgpcc_public_jwks()
    req = PresentedRequest(_ACT, _AUD, _PARAMS)
    for missing in (None, "", {}, {"token": ""}):
        chk = verify_tgpcc(missing, req, None, jwks, pinned_epoch=0)
        assert chk.ok is False, missing
        assert chk.reason == "no artifact", missing


# --------------------------------------------------------------------------- #
# 3. REPLAY — happy-path token presented for a DIFFERENT request => DENY.      #
# --------------------------------------------------------------------------- #


def test_capstone_replay_denies_at_intent_commit(monkeypatch) -> None:
    """The happy-path token, presented to the resource for a DIFFERENT call
    (attacker recipient), DENYs at intent_commit — the signed intent no longer
    matches the presented request (confused-deputy / replay defense)."""
    _full_env(monkeypatch)
    nodes = [
        OperandNode(
            "u1", "user-task", CapabilityLevel.TRUSTED, ConfidentialityLevel.PUBLIC
        ),
    ]
    label_fields = _producer_label_fields(
        nodes=nodes,
        integrity=CapabilityLevel.TRUSTED,
        confidentiality=ConfidentialityLevel.PUBLIC,
        label_id="user-task",
    )
    holder = Ed25519PrivateKey.generate()
    proof = _mint_bind_proof(holder, audience=_AUD, action=_ACT)
    resp = _client(_FakeGovernance(_permit_outcome())).post(
        "/v1/govern/mint",
        json={
            "action_type": _ACT,
            "content": "ok",
            "recipient": _AUD,
            "dpop_proof": proof,
            **label_fields,
        },
    )
    assert resp.status_code == 200, resp.text
    token = resp.json()["access_token"]
    claims = _decode_claims(token)
    now = claims["iat"]
    use_proof = _use_proof(holder, token, now)
    jwks = tgpcc_public_jwks()

    # Present the SAME token for a DIFFERENT request (redirected recipient).
    tampered = PresentedRequest(
        _ACT, _AUD, {"to": "attacker.example", "subject": "drained"}
    )
    chk = verify_tgpcc(token, tampered, use_proof, jwks, pinned_epoch=None, now=now)
    assert chk.ok is False
    assert chk.reason == "intent mismatch"

    # Sanity: presenting it for its OWN committed call still PERMITs (the bind is
    # exact, not blanket-deny — this is the discriminating leg).
    ok = verify_tgpcc(
        token, PresentedRequest(_ACT, _AUD, _PARAMS), use_proof, jwks, None, now=now
    )
    assert ok.ok is True, ok.reason


# --------------------------------------------------------------------------- #
# 4. TAMPER — flip the embedded prov_commit label in the SIGNED token => DENY #
#    'bad signature' (the label is signature-covered, not advisory).          #
# --------------------------------------------------------------------------- #


def test_capstone_tampered_prov_label_denies_bad_signature(monkeypatch) -> None:
    """Flipping the embedded ``prov_commit`` label TRUSTED->UNTRUSTED inside the
    signed token DENYs with 'bad signature' — the integrity label is COVERED by
    the Ed25519 signature, so a tainted label cannot be laundered to TRUSTED
    after issuance (and an attacker cannot forge the signature to match)."""
    _full_env(monkeypatch)
    nodes = [
        OperandNode(
            "u1", "user-task", CapabilityLevel.TRUSTED, ConfidentialityLevel.PUBLIC
        ),
    ]
    label_fields = _producer_label_fields(
        nodes=nodes,
        integrity=CapabilityLevel.TRUSTED,
        confidentiality=ConfidentialityLevel.PUBLIC,
        label_id="user-task",
    )
    holder = Ed25519PrivateKey.generate()
    proof = _mint_bind_proof(holder, audience=_AUD, action=_ACT)
    resp = _client(_FakeGovernance(_permit_outcome())).post(
        "/v1/govern/mint",
        json={
            "action_type": _ACT,
            "content": "ok",
            "recipient": _AUD,
            "dpop_proof": proof,
            **label_fields,
        },
    )
    assert resp.status_code == 200, resp.text
    token = resp.json()["access_token"]
    body, _, sig = token.partition(".")
    claims = _decode_claims(token)
    now = claims["iat"]
    use_proof = _use_proof(holder, token, now)
    jwks = tgpcc_public_jwks()

    # Confirm the honest baseline FIRST: the unmodified token PERMITs (so the
    # DENY below is attributable to the tamper, not some unrelated failure).
    base_chk = verify_tgpcc(
        token, PresentedRequest(_ACT, _AUD, _PARAMS), use_proof, jwks, None, now=now
    )
    assert base_chk.ok is True, base_chk.reason
    assert claims["prov_commit"]["label"]["integrity"] == int(CapabilityLevel.TRUSTED)

    # TAMPER: mutate the SIGNED label TRUSTED(0) -> UNTRUSTED(2), re-encode the
    # body, keep the ORIGINAL signature. (Compact, sorted-key re-encode to match
    # the broker's canonical body recipe — though ANY re-encode breaks the sig.)
    claims["prov_commit"]["label"]["integrity"] = int(CapabilityLevel.UNTRUSTED)
    forged_body = (
        base64.urlsafe_b64encode(
            json.dumps(claims, sort_keys=True, separators=(",", ":")).encode("utf-8")
        )
        .rstrip(b"=")
        .decode("ascii")
    )
    forged = f"{forged_body}.{sig}"

    # The use-proof was bound to the ORIGINAL token; rebind it to the forged
    # token so the DENY is unambiguously the SIGNATURE leg, not a PoP-bind miss.
    forged_use_proof = _use_proof(holder, forged, now)
    chk = verify_tgpcc(
        forged,
        PresentedRequest(_ACT, _AUD, _PARAMS),
        forged_use_proof,
        jwks,
        pinned_epoch=None,
        now=now,
    )
    assert chk.ok is False
    assert chk.reason == "bad signature"
