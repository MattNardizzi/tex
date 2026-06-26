"""Taint-Gated Mint (TG-PCC B1+) — the "Injection-Mints-Nothing" named-property
test, the load-bearing claim of the one beyond-frontier leg, wired as a CI
FALSIFIER.

THE CLAIM UNDER TEST
--------------------
An action whose operands derive from UNTRUSTED / quarantined data is
*structurally* unable to obtain a Tex capability token: the integrity label is a
PRECONDITION OF THE SIGNATURE EXISTING, not a guard consulted after signing. The
label is AGENT-INDEPENDENT — it is stamped + HMAC-signed by a trusted label
producer (the in-path PEP / CaMeL interpreter / quarantine store) with an
operator secret (``TEX_TAINT_LABEL_SECRET``) the calling agent does not hold. The
agent therefore cannot raise its own integrity; it can only present a producer's
attestation, which mint VERIFIES before it will sign.

  (A) same high-integrity action, operands from the trusted user task,
      meet ⊒ floor  -> mint SUCCEEDS, TG-PCC issued, prov_commit.label.integrity =
      TRUSTED; an offline verify PERMITs (signature + label-floor + intent).
  (B) identical action, one operand derives from quarantined/untrusted data ->
      mint returns NO token; the broker SIGNING PATH is asserted UNREACHED (the
      signer is patched to raise on call).
  (C) feed A's successful token into request (B)'s intent -> offline verify DENYs
      at intent_commit (the presented call != the committed call).

FALSIFIER WIRING: the under-floor case (B) asserts a hard 403 + signer
never-called; if the gate ever MINTS in the under-floor case the patched signer
raises (AssertionError) and/or the status is 200 — either way the test FAILS
LOUDLY in CI. Per the contract: a test that EXPECTS a mint in the under-floor
case MUST FAIL. If (B) ever mints, the whole TG-PCC novelty downgrades to PARITY.

HONESTY (no overclaim): this is ISSUANCE-gating, not in-path blocking. "Injection
mints nothing" means an injection-tainted operand cannot OBTAIN a Tex credential
— it does not, by itself, stop an agent that bypasses Tex and calls the resource
directly. The label assessor is in the TCB. Beyond-frontier ONLY on the
integrity / untrusted-derivation vector; parity elsewhere.

Default-OFF behind ``TEX_TAINT_GATED_MINT``: with the flag unset the new leg is
inert and B1 behaves byte-for-byte as today.
"""

from __future__ import annotations

import base64
from unittest import mock
from uuid import uuid4

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi import FastAPI
from fastapi.testclient import TestClient

from tex.api.auth import TexPrincipal, authenticate_request
from tex.api.governance_standing_routes import build_governance_standing_router
from tex.authority import pop
from tex.authority.broker import (
    canonical_intent_commit,
    tgpcc_public_jwks,
    verify_prov_commit_floor,
    verify_with_jwks,
)
from tex.authority.taint_label import (
    OperandNode,
    ProvenanceCommitment,
    compute_lineage_root,
    meet_label,
    sign_label_envelope,
)
from tex.camel.capability import (
    Capability,
    CapabilityLevel,
    CapabilitySet,
    ConfidentialityLevel,
    FidesLabel,
)
from tex.domain.verdict import Verdict
from tex.governance.standing import DecisionOutcome

SECRET = "shared-authority-signing-secret"
PRODUCER_SECRET = "operator-held-label-producer-secret"

_AUD = "payroll.example"
_ACT = "send_email"


# --------------------------------------------------------------------------- #
# Harness — reuse the B1 shape verbatim                                        #
# --------------------------------------------------------------------------- #


class _FakeGovernance:
    """Records decide() kwargs and returns a pre-seeded DecisionOutcome."""

    def __init__(self, outcome: DecisionOutcome) -> None:
        self._outcome = outcome
        self.last_kwargs: dict | None = None

    def decide(self, **kwargs) -> DecisionOutcome:
        self.last_kwargs = kwargs
        return self._outcome


def _client(gov: object | None) -> TestClient:
    app = FastAPI()
    app.include_router(build_governance_standing_router())
    if gov is not None:
        app.state.standing_governance = gov
    app.dependency_overrides[authenticate_request] = lambda: TexPrincipal(
        api_key_fingerprint="test",
        tenant="acme",
        scopes=frozenset({"decision:write"}),
    )
    return TestClient(app)


def _permit_outcome(**over) -> DecisionOutcome:
    base = dict(
        verdict=Verdict.PERMIT,
        released=True,
        reason="released by deep adjudication",
        tier="deep",
        decision_id=uuid4(),
        evidence_hash="abc123",
    )
    base.update(over)
    return DecisionOutcome(**base)


def _dpop_proof(priv: Ed25519PrivateKey, *, audience: str, action: str) -> tuple[str, str]:
    jkt = pop.thumbprint(priv.public_key())
    bind = f"tex-pop-mint:{jkt}:{audience}:{action}"
    proof = pop.make_pop_proof(priv, bind=bind)
    return proof, jkt


def _pin_ed25519_key(monkeypatch) -> Ed25519PrivateKey:
    """Pin a stable TG-PCC Ed25519 signing key so the route signs asymmetrically
    and the published JWKS resolves the same key (for offline verify)."""
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


def _producer_label_fields(
    *,
    integrity: CapabilityLevel,
    confidentiality: ConfidentialityLevel,
    floor: FidesLabel,
    lineage_root: str,
    label_id: str,
    aud: str = _AUD,
    act: str = _ACT,
) -> dict:
    """The trusted-producer-signed label fields the caller PRESENTS. The
    signature is computed with the operator PRODUCER_SECRET — an agent that does
    not hold the secret cannot forge it (that is the agent-independence)."""
    commit = ProvenanceCommitment(
        label=FidesLabel(integrity=integrity, confidentiality=confidentiality),
        floor=floor,
        lineage_root=lineage_root,
        label_id=label_id,
        aud=aud,
        act=act,
    )
    sig = sign_label_envelope(commit, secret=PRODUCER_SECRET)
    return {
        "operand_label_integrity": int(integrity),
        "operand_label_confidentiality": int(confidentiality),
        "operand_label_id": label_id,
        "lineage_root": lineage_root,
        "label_signature": sig,
        "intent_method": act,
        "intent_resource": aud,
        "intent_params": {"to": aud, "subject": "ok"},
    }


def _taint_env(monkeypatch) -> None:
    monkeypatch.setenv("TEX_GOVERN_MINT", "1")
    monkeypatch.setenv("TEX_AUTHORITY_SIGNING_SECRET", SECRET)
    monkeypatch.setenv("TEX_TAINT_GATED_MINT", "1")
    monkeypatch.setenv("TEX_TAINT_LABEL_SECRET", PRODUCER_SECRET)
    monkeypatch.setenv("TEX_APP_ENV", "test")


# --------------------------------------------------------------------------- #
# The label IS agent-independent: the meet comes from the producer lattice     #
# --------------------------------------------------------------------------- #


def test_meet_is_producer_set_not_agent_asserted() -> None:
    """The operand meet floors to UNTRUSTED the moment any untrusted ancestor is
    present — regardless of what the agent might claim. The label is the
    high-water-mark join over PRODUCER-set Capability tags, not a request field."""
    trusted_a = Capability.trusted(source="system")
    untrusted_b = Capability.untrusted(
        source="email_body", confidentiality=ConfidentialityLevel.CONFIDENTIAL
    )
    # Pure trusted operand -> TRUSTED meet.
    assert CapabilitySet.of(trusted_a).level == CapabilityLevel.TRUSTED
    # One untrusted ancestor -> the whole derived operand is UNTRUSTED.
    derived = CapabilitySet.of(trusted_a, untrusted_b)
    assert derived.level == CapabilityLevel.UNTRUSTED
    assert derived.is_untrusted

    # The OperandNode meet helper agrees.
    nodes = [
        OperandNode("a", "lbl-a", CapabilityLevel.TRUSTED, ConfidentialityLevel.PUBLIC),
        OperandNode(
            "b", "lbl-b", CapabilityLevel.UNTRUSTED, ConfidentialityLevel.CONFIDENTIAL
        ),
    ]
    label = meet_label(nodes)
    assert label.integrity == CapabilityLevel.UNTRUSTED
    assert label.confidentiality == ConfidentialityLevel.CONFIDENTIAL


# --------------------------------------------------------------------------- #
# (A) trusted operand — mint SUCCEEDS, prov_commit carried, offline verify OK  #
# --------------------------------------------------------------------------- #


def test_A_trusted_operand_mints(monkeypatch) -> None:
    _taint_env(monkeypatch)
    sk = _pin_ed25519_key(monkeypatch)
    outcome = _permit_outcome()

    # A trusted-only operand DAG -> meet = TRUSTED, dominates the default floor.
    nodes = [
        OperandNode("u1", "user-task", CapabilityLevel.TRUSTED, ConfidentialityLevel.PUBLIC),
    ]
    lineage = compute_lineage_root(nodes)
    label_fields = _producer_label_fields(
        integrity=CapabilityLevel.TRUSTED,
        confidentiality=ConfidentialityLevel.PUBLIC,
        floor=FidesLabel(
            integrity=CapabilityLevel.TRUSTED, confidentiality=ConfidentialityLevel.PUBLIC
        ),
        lineage_root=lineage,
        label_id="user-task",
    )

    priv = Ed25519PrivateKey.generate()
    proof, jkt = _dpop_proof(priv, audience=_AUD, action=_ACT)
    resp = _client(_FakeGovernance(outcome)).post(
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
    assert payload["cnf"]["jkt"] == jkt

    # The token is Ed25519-signed (TG-PCC plane on) and carries the SIGNED
    # prov_commit + intent_commit. Offline verify PERMITs.
    jwks = tgpcc_public_jwks()
    assert jwks["keys"], "published JWKS must carry the signing key"
    # The body claims iat == issuance; verify within window.
    body_b64 = token.partition(".")[0]
    import json as _json

    claims = _json.loads(base64.urlsafe_b64decode(body_b64 + "=" * (-len(body_b64) % 4)))
    now = claims["iat"]

    chk = verify_with_jwks(token, jwks, now=now)
    assert chk.ok is True, chk.reason
    assert chk.claims["prov_commit"]["label"]["integrity"] == int(CapabilityLevel.TRUSTED)
    # The floor re-check (label ⊒ floor) PERMITs offline from the signed claims.
    floor_chk = verify_prov_commit_floor(chk.claims)
    assert floor_chk.ok is True, floor_chk.reason
    # And the intent_commit matches the producer-attested action intent.
    expected_ic = canonical_intent_commit(_ACT, _AUD, {"to": _AUD, "subject": "ok"})
    ic_chk = verify_with_jwks(token, jwks, now=now, expected_intent_commit=expected_ic)
    assert ic_chk.ok is True, ic_chk.reason

    # Sanity: the verifying JWKS key is the signing key's public half.
    raw = sk.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    assert jwks["keys"][0]["x"] == pop.public_jwk(raw)["x"]


# --------------------------------------------------------------------------- #
# (B) injected/untrusted operand — mint NOTHING + signing path UNREACHED       #
#     THE FALSIFIER: an erroneous mint here FAILS the suite                     #
# --------------------------------------------------------------------------- #


def test_B_injected_operand_mints_nothing_and_signer_unreached(monkeypatch) -> None:
    _taint_env(monkeypatch)
    _pin_ed25519_key(monkeypatch)
    outcome = _permit_outcome()  # PERMIT — the ONLY thing that can refuse is taint

    # One operand derives from quarantined/untrusted data -> meet = UNTRUSTED,
    # which is under the default TRUSTED floor.
    nodes = [
        OperandNode("u1", "user-task", CapabilityLevel.TRUSTED, ConfidentialityLevel.PUBLIC),
        OperandNode(
            "e1", "email_body", CapabilityLevel.UNTRUSTED, ConfidentialityLevel.CONFIDENTIAL
        ),
    ]
    meet = meet_label(nodes)
    assert meet.integrity == CapabilityLevel.UNTRUSTED  # the injection floors it
    lineage = compute_lineage_root(nodes)
    label_fields = _producer_label_fields(
        integrity=meet.integrity,
        confidentiality=meet.confidentiality,
        floor=FidesLabel(
            integrity=CapabilityLevel.TRUSTED, confidentiality=ConfidentialityLevel.PUBLIC
        ),
        lineage_root=lineage,
        label_id="email_body",
    )

    priv = Ed25519PrivateKey.generate()
    proof, _ = _dpop_proof(priv, audience=_AUD, action=_ACT)

    # FALSIFIER: patch the broker SIGNING path (source module class method). The
    # route imports CredentialBroker lazily off tex.authority.broker, so a
    # source-module patch intercepts it. If the gate WRONGLY mints, the signer is
    # reached and raises -> the test FAILS LOUDLY in CI.
    spy = mock.Mock(side_effect=AssertionError("signer reached on under-floor mint"))
    monkeypatch.setattr("tex.authority.broker.CredentialBroker.mint", spy)

    resp = _client(_FakeGovernance(outcome)).post(
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
    # The signer was provably NEVER reached — the short-circuit lands between the
    # released-check (E) and broker.mint (I).
    spy.assert_not_called()
    assert spy.call_count == 0


def test_B_forged_label_signature_mints_nothing(monkeypatch) -> None:
    """An agent that FAKES a trusted label (without the producer secret) cannot
    pass — the signature does not verify, so mint refuses fail-closed. This is the
    core agent-independence: a self-asserted 'trusted' label is rejected."""
    _taint_env(monkeypatch)
    _pin_ed25519_key(monkeypatch)
    outcome = _permit_outcome()

    # The agent claims TRUSTED (which WOULD dominate the floor) but signs with the
    # WRONG secret (it does not hold TEX_TAINT_LABEL_SECRET).
    commit = ProvenanceCommitment(
        label=FidesLabel(
            integrity=CapabilityLevel.TRUSTED, confidentiality=ConfidentialityLevel.PUBLIC
        ),
        floor=FidesLabel(
            integrity=CapabilityLevel.TRUSTED, confidentiality=ConfidentialityLevel.PUBLIC
        ),
        lineage_root=compute_lineage_root(
            [OperandNode("x", "x", CapabilityLevel.TRUSTED, ConfidentialityLevel.PUBLIC)]
        ),
        label_id="forged",
        aud=_AUD,
        act=_ACT,
    )
    forged_sig = sign_label_envelope(commit, secret="agent-guessed-secret")

    priv = Ed25519PrivateKey.generate()
    proof, _ = _dpop_proof(priv, audience=_AUD, action=_ACT)
    spy = mock.Mock(side_effect=AssertionError("signer reached on forged-label mint"))
    monkeypatch.setattr("tex.authority.broker.CredentialBroker.mint", spy)

    resp = _client(_FakeGovernance(outcome)).post(
        "/v1/govern/mint",
        json={
            "action_type": _ACT,
            "content": "trust me",
            "recipient": _AUD,
            "dpop_proof": proof,
            "operand_label_integrity": int(CapabilityLevel.TRUSTED),
            "operand_label_confidentiality": int(ConfidentialityLevel.PUBLIC),
            "operand_label_id": "forged",
            "lineage_root": commit.lineage_root,
            "label_signature": forged_sig,
        },
    )
    assert resp.status_code == 403, resp.text
    assert "access_token" not in resp.json()
    assert "signature invalid" in resp.json()["reason"]
    spy.assert_not_called()


def test_B_absent_label_fails_closed(monkeypatch) -> None:
    """Flag-on, but NO producer label presented => fail-closed refuse (absence of
    an agent-independent label means 'treat as tainted', never permit)."""
    _taint_env(monkeypatch)
    _pin_ed25519_key(monkeypatch)
    outcome = _permit_outcome()
    priv = Ed25519PrivateKey.generate()
    proof, _ = _dpop_proof(priv, audience=_AUD, action=_ACT)
    spy = mock.Mock(side_effect=AssertionError("signer reached on no-label mint"))
    monkeypatch.setattr("tex.authority.broker.CredentialBroker.mint", spy)
    resp = _client(_FakeGovernance(outcome)).post(
        "/v1/govern/mint",
        json={
            "action_type": _ACT,
            "content": "no label at all",
            "recipient": _AUD,
            "dpop_proof": proof,
        },
    )
    assert resp.status_code == 403, resp.text
    assert "access_token" not in resp.json()
    assert resp.json()["reason"].startswith("insufficient_integrity")
    spy.assert_not_called()


def test_B_no_producer_secret_fails_closed(monkeypatch) -> None:
    """Flag-on but the operator producer secret is UNSET => no label can be
    verified => fail-closed refuse, even with a well-formed presented label."""
    monkeypatch.setenv("TEX_GOVERN_MINT", "1")
    monkeypatch.setenv("TEX_AUTHORITY_SIGNING_SECRET", SECRET)
    monkeypatch.setenv("TEX_TAINT_GATED_MINT", "1")
    monkeypatch.delenv("TEX_TAINT_LABEL_SECRET", raising=False)
    monkeypatch.setenv("TEX_APP_ENV", "test")
    _pin_ed25519_key(monkeypatch)
    outcome = _permit_outcome()
    label_fields = _producer_label_fields(
        integrity=CapabilityLevel.TRUSTED,
        confidentiality=ConfidentialityLevel.PUBLIC,
        floor=FidesLabel(
            integrity=CapabilityLevel.TRUSTED, confidentiality=ConfidentialityLevel.PUBLIC
        ),
        lineage_root="abc",
        label_id="x",
    )
    priv = Ed25519PrivateKey.generate()
    proof, _ = _dpop_proof(priv, audience=_AUD, action=_ACT)
    resp = _client(_FakeGovernance(outcome)).post(
        "/v1/govern/mint",
        json={
            "action_type": _ACT,
            "content": "x",
            "recipient": _AUD,
            "dpop_proof": proof,
            **label_fields,
        },
    )
    assert resp.status_code == 403, resp.text
    assert "access_token" not in resp.json()


# --------------------------------------------------------------------------- #
# (C) replay — A's token presented for B's intent DENYs at intent_commit       #
# --------------------------------------------------------------------------- #


def test_C_replay_denies_at_intent_commit(monkeypatch) -> None:
    """Mint A's token (intent = action A), then present it OFFLINE against a
    DIFFERENT intent B. The signed intent_commit no longer matches => DENY."""
    _taint_env(monkeypatch)
    sk = _pin_ed25519_key(monkeypatch)
    outcome = _permit_outcome()

    nodes = [OperandNode("u1", "user-task", CapabilityLevel.TRUSTED, ConfidentialityLevel.PUBLIC)]
    label_fields = _producer_label_fields(
        integrity=CapabilityLevel.TRUSTED,
        confidentiality=ConfidentialityLevel.PUBLIC,
        floor=FidesLabel(
            integrity=CapabilityLevel.TRUSTED, confidentiality=ConfidentialityLevel.PUBLIC
        ),
        lineage_root=compute_lineage_root(nodes),
        label_id="user-task",
    )
    # A's committed intent params.
    paramsA = {"to": _AUD, "subject": "ok"}
    label_fields["intent_params"] = paramsA

    priv = Ed25519PrivateKey.generate()
    proof, _ = _dpop_proof(priv, audience=_AUD, action=_ACT)
    resp = _client(_FakeGovernance(outcome)).post(
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
    token_A = resp.json()["access_token"]

    jwks = tgpcc_public_jwks()
    import json as _json

    body_b64 = token_A.partition(".")[0]
    claims = _json.loads(base64.urlsafe_b64decode(body_b64 + "=" * (-len(body_b64) % 4)))
    now = claims["iat"]

    # Request B is a DIFFERENT call (different params) -> different intent_commit.
    paramsB = {"to": "attacker.example", "subject": "drained"}
    intent_commit_B = canonical_intent_commit(_ACT, _AUD, paramsB)
    intent_commit_A = canonical_intent_commit(_ACT, _AUD, paramsA)
    assert intent_commit_B != intent_commit_A

    # Presenting A's token for B's intent DENYs at the intent binding.
    chk = verify_with_jwks(token_A, jwks, now=now, expected_intent_commit=intent_commit_B)
    assert chk.ok is False
    assert chk.reason == "intent mismatch"

    # Presenting it for its OWN intent still PERMITs (sanity — the binding is
    # exact, not blanket-deny).
    ok = verify_with_jwks(token_A, jwks, now=now, expected_intent_commit=intent_commit_A)
    assert ok.ok is True


def test_C_replay_under_socketless_offline(monkeypatch) -> None:
    """The (C) DENY is provably OFFLINE — no socket is opened during verify."""
    import socket as _socket

    _taint_env(monkeypatch)
    _pin_ed25519_key(monkeypatch)
    outcome = _permit_outcome()
    nodes = [OperandNode("u1", "user-task", CapabilityLevel.TRUSTED, ConfidentialityLevel.PUBLIC)]
    label_fields = _producer_label_fields(
        integrity=CapabilityLevel.TRUSTED,
        confidentiality=ConfidentialityLevel.PUBLIC,
        floor=FidesLabel(
            integrity=CapabilityLevel.TRUSTED, confidentiality=ConfidentialityLevel.PUBLIC
        ),
        lineage_root=compute_lineage_root(nodes),
        label_id="user-task",
    )
    priv = Ed25519PrivateKey.generate()
    proof, _ = _dpop_proof(priv, audience=_AUD, action=_ACT)
    resp = _client(_FakeGovernance(outcome)).post(
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
    token_A = resp.json()["access_token"]
    jwks = tgpcc_public_jwks()
    import json as _json

    body_b64 = token_A.partition(".")[0]
    claims = _json.loads(base64.urlsafe_b64decode(body_b64 + "=" * (-len(body_b64) % 4)))
    now = claims["iat"]

    def _boom(*a, **k):
        raise AssertionError("air-gap violated: a socket was opened during verify")

    monkeypatch.setattr(_socket, "socket", _boom)
    bad = canonical_intent_commit(_ACT, _AUD, {"to": "attacker.example"})
    chk = verify_with_jwks(token_A, jwks, now=now, expected_intent_commit=bad)
    assert chk.ok is False
    assert chk.reason == "intent mismatch"


# --------------------------------------------------------------------------- #
# DEFAULT-OFF inertness — with the taint flag unset B1 is byte-for-byte today   #
# --------------------------------------------------------------------------- #


def test_default_off_taint_inert_still_mints(monkeypatch) -> None:
    """TEX_GOVERN_MINT on, but TEX_TAINT_GATED_MINT UNSET: the taint leg is inert
    and a PERMIT mints exactly as in B1 — no label required, NO prov_commit/
    intent_commit embedded, default HMAC signing (no alg claim)."""
    monkeypatch.setenv("TEX_GOVERN_MINT", "1")
    monkeypatch.setenv("TEX_AUTHORITY_SIGNING_SECRET", SECRET)
    monkeypatch.delenv("TEX_TAINT_GATED_MINT", raising=False)
    monkeypatch.delenv("TEX_TAINT_LABEL_SECRET", raising=False)
    monkeypatch.setenv("TEX_APP_ENV", "test")
    outcome = _permit_outcome()
    priv = Ed25519PrivateKey.generate()
    proof, jkt = _dpop_proof(priv, audience=_AUD, action=_ACT)
    resp = _client(_FakeGovernance(outcome)).post(
        "/v1/govern/mint",
        json={
            "action_type": _ACT,
            "content": "hi",
            "recipient": _AUD,
            "dpop_proof": proof,
            "ttl": 120,
        },
    )
    assert resp.status_code == 200, resp.text
    payload = resp.json()
    token = payload["access_token"]
    assert token
    assert payload["cnf"]["jkt"] == jkt
    # The token is the pre-B1+ HMAC shape: no alg claim, no prov_commit, no
    # intent_commit in the signed body.
    import json as _json

    body_b64 = token.partition(".")[0]
    claims = _json.loads(base64.urlsafe_b64decode(body_b64 + "=" * (-len(body_b64) % 4)))
    assert "alg" not in claims
    assert "prov_commit" not in claims
    assert "intent_commit" not in claims


def test_default_off_taint_inert_even_with_untrusted_label(monkeypatch) -> None:
    """With the taint flag OFF, even an UNTRUSTED presented label is ignored —
    the route does not gate on it (B1 parity). Proves the gate lives entirely
    behind the flag and the default path is unchanged."""
    monkeypatch.setenv("TEX_GOVERN_MINT", "1")
    monkeypatch.setenv("TEX_AUTHORITY_SIGNING_SECRET", SECRET)
    monkeypatch.delenv("TEX_TAINT_GATED_MINT", raising=False)
    monkeypatch.setenv("TEX_APP_ENV", "test")
    outcome = _permit_outcome()
    priv = Ed25519PrivateKey.generate()
    proof, _ = _dpop_proof(priv, audience=_AUD, action=_ACT)
    resp = _client(_FakeGovernance(outcome)).post(
        "/v1/govern/mint",
        json={
            "action_type": _ACT,
            "content": "hi",
            "recipient": _AUD,
            "dpop_proof": proof,
            # An UNTRUSTED label is present, but the flag is off so it is ignored.
            "operand_label_integrity": int(CapabilityLevel.UNTRUSTED),
            "operand_label_confidentiality": int(ConfidentialityLevel.CONFIDENTIAL),
            "operand_label_id": "ignored",
            "lineage_root": "ignored",
            "label_signature": "ignored",
        },
    )
    # Flag off => taint gate never runs => the PERMIT mints (B1 behavior).
    assert resp.status_code == 200, resp.text
    assert resp.json()["access_token"]
