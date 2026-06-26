"""TG-PCC B1+ — the "Live-Fed-Gate" named-property test: TEX'S OWN PDP is the
agent-INDEPENDENT label producer feeding the E2 taint gate on the REAL
``POST /v1/govern/mint`` route, with NO caller-supplied label and NO test
playing the producer.

THE PROPERTY UNDER TEST
-----------------------
With ``TEX_TAINT_LABEL_LIVE=1`` (+ ``TEX_TAINT_GATED_MINT=1`` +
``TEX_TAINT_LABEL_SECRET``), and with the ``MintRequest`` carrying NONE of the
producer fields (``operand_label_integrity`` / ``operand_label_confidentiality``
/ ``operand_label_id`` / ``lineage_root`` / ``label_signature``), the mint
outcome is driven SOLELY by the integrity label Tex's PDP computed for the
ruling. The agent cannot supply or raise its own label.

The label is REAL — it comes from the live ``IfcSpecialist`` classifier run on
the request inside a real ``StandingGovernance.decide()`` path (NOT a stub, NOT
a caller field). The classifier labels ``request.content`` ``USER_INPUT`` by
default and drops it to ``TOOL_UNTRUSTED`` only on an operator/PEP-set
``content_origin`` / ``untrusted_source`` metadata marker — markers the agent
cannot set through the mint body (they are ``EvaluationRequest.metadata`` keys,
never ``MintRequest`` fields). That is the substance of agent-independence.

  (A) PDP classifies the source UNTRUSTED  -> meet ⋢ floor -> 403, NO token,
      ``broker.mint`` PROVABLY UNREACHED (the signer is patched to raise).
  (B) PDP classifies a TRUSTED source (operator-relaxed floor) -> mint SUCCEEDS,
      and the issued token's ``prov_commit.label_id`` is
      ``pdp:{decision_id}:{evidence_hash}`` — bound to TEX'S ruling, with NO
      corresponding field anywhere in the request body.
  (C) NOT-CIRCULAR / anti-forge: the caller injects a forged TRUSTED label +
      fabricated signature on the SAME untrusted request -> STILL 403. A
      self-asserted "trusted" label does NOT change the outcome — the route
      reads ``outcome.integrity_label`` (the PDP's), never ``body.operand_*``.
  (D) Missing producer secret under the live flag -> fail-closed 403.

GRANULARITY CEILING (stated plainly; do NOT read this test as proving more): the
PDP label is a SINGLE-REQUEST SOURCE classification, strictly COARSER than full
operand-lineage. It CANNOT catch an injection laundered as trusted-looking
USER_INPUT — that needs a multi-hop operand DAG through the CaMeL runtime, which
is NOT on the decide()/mint path. The ``lineage_root`` here is a degenerate
single-node commitment. This test proves the gate is now FED by an
agent-independent PDP label for source-classifiable cases, NOT that the
multi-hop-injection vector is closed.

Default-OFF: with ``TEX_TAINT_LABEL_LIVE`` unset the legacy caller-presented
path runs byte-for-byte (covered by ``test_taint_gated_mint.py``); the inertness
guard at the bottom re-asserts the default boot is unchanged.
"""

from __future__ import annotations

import base64
import json as _json
from datetime import UTC, datetime
from unittest import mock
from uuid import uuid4

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi import FastAPI
from fastapi.testclient import TestClient

from tex.api.auth import TexPrincipal, authenticate_request
from tex.api.governance_standing_routes import (
    _INTEGRITY_FLOOR,
    build_governance_standing_router,
)
from tex.authority import pop
from tex.authority.broker import tgpcc_public_jwks, verify_prov_commit_floor, verify_with_jwks
from tex.camel.capability import CapabilityLevel, ConfidentialityLevel, FidesLabel
from tex.domain.evaluation import EvaluationResponse
from tex.domain.retrieval import RetrievalContext
from tex.domain.verdict import Verdict
from tex.governance.standing import StandingGovernance
from tex.specialists.ifc_specialist import IfcSpecialist, get_ifc_labels_cache

SECRET = "shared-authority-signing-secret"
PRODUCER_SECRET = "operator-held-label-producer-secret"

_AUD = "payroll.example"
_ACT = "send_email"


# --------------------------------------------------------------------------- #
# REAL decide() harness — a real StandingGovernance whose deep tier runs the    #
# REAL IfcSpecialist classifier, so the integrity label is genuinely PDP-       #
# computed (not a stub, not a caller field).                                    #
# --------------------------------------------------------------------------- #


class _Agent:
    """A sealed, governable, in-surface agent (None surface => trivially in
    bounds) so decide() reaches the deep tier and can PERMIT."""

    def __init__(self, agent_id):
        self.agent_id = agent_id
        self.tenant_id = "acme"
        self.lifecycle_status = "ACTIVE"
        self.capability_surface = None
        self.external_agent_id = None
        self.name = None


class _OneAgentRegistry:
    def __init__(self, agent):
        self._agent = agent

    def get(self, uid):
        return self._agent if uid == self._agent.agent_id else None

    def list_all(self):
        return [self._agent]


class _RealIfcEvaluate:
    """A deep PDP that PERMITs but runs the REAL IfcSpecialist classifier and
    surfaces its label on a ``Decision``-shaped result, exactly as the live PDP
    does (``pdp.py`` pops ``get_ifc_labels_cache()`` onto
    ``Decision.metadata['ifc_labels']``). The integrity label is therefore Tex's
    own classification of ``request.content`` + request metadata — NOT a caller
    field and NOT a fabricated value."""

    class _Result:
        def __init__(self, response, decision):
            self.response = response
            self.decision = decision

    class _Decision:
        def __init__(self, metadata):
            self.metadata = metadata

    def execute(self, request):
        # Run the REAL classifier (same engine the live PDP uses) and read its
        # serialized label out of the consume-once cache, mirroring pdp.py.
        spec = IfcSpecialist()
        spec.evaluate(request=request, retrieval_context=RetrievalContext.empty())
        ifc_labels = get_ifc_labels_cache().pop(request_id=str(request.request_id))
        decision_id = uuid4()
        response = EvaluationResponse(
            decision_id=decision_id,
            verdict=Verdict.PERMIT,
            confidence=0.99,
            final_score=0.01,
            reasons=["released by deep adjudication"],
            policy_version="test",
            evidence_hash="evh-" + decision_id.hex[:8],
            evaluated_at=datetime.now(UTC),
        )
        metadata = {}
        if ifc_labels is not None:
            metadata["ifc_labels"] = ifc_labels
        decision = self._Decision(metadata)
        return self._Result(response, decision)


def _gov(agent) -> StandingGovernance:
    return StandingGovernance(
        agent_registry=_OneAgentRegistry(agent),
        evaluate_command=_RealIfcEvaluate(),
    )


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


def _dpop_proof(priv: Ed25519PrivateKey, *, audience: str, action: str) -> tuple[str, str]:
    jkt = pop.thumbprint(priv.public_key())
    bind = f"tex-pop-mint:{jkt}:{audience}:{action}"
    proof = pop.make_pop_proof(priv, bind=bind)
    return proof, jkt


def _pin_ed25519_key(monkeypatch) -> Ed25519PrivateKey:
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


def _live_env(monkeypatch) -> None:
    monkeypatch.setenv("TEX_GOVERN_MINT", "1")
    monkeypatch.setenv("TEX_AUTHORITY_SIGNING_SECRET", SECRET)
    monkeypatch.setenv("TEX_TAINT_GATED_MINT", "1")
    monkeypatch.setenv("TEX_TAINT_LABEL_LIVE", "1")  # the live producer is ON
    monkeypatch.setenv("TEX_TAINT_LABEL_SECRET", PRODUCER_SECRET)
    monkeypatch.setenv("TEX_APP_ENV", "test")


def _relax_floor(monkeypatch, *, aud: str, act: str, floor: FidesLabel) -> None:
    """Operator-side floor relaxation for one (aud, act) — operator CODE, never a
    request field. Patched into the module map and restored after the test."""
    monkeypatch.setitem(_INTEGRITY_FLOOR, (aud, act), floor)


# --------------------------------------------------------------------------- #
# (A) PDP classifies the source UNTRUSTED -> mint NOTHING, signer UNREACHED     #
#     — and the caller supplied NO label fields at all.                         #
# --------------------------------------------------------------------------- #


def test_live_A_untrusted_source_mints_nothing_no_caller_label(monkeypatch) -> None:
    _live_env(monkeypatch)
    _pin_ed25519_key(monkeypatch)
    agent_id = uuid4()
    gov = _gov(_Agent(agent_id))

    priv = Ed25519PrivateKey.generate()
    proof, _ = _dpop_proof(priv, audience=_AUD, action=_ACT)

    # FALSIFIER: if the gate WRONGLY mints, the signer is reached and raises.
    spy = mock.Mock(side_effect=AssertionError("signer reached on under-floor live mint"))
    monkeypatch.setattr("tex.authority.broker.CredentialBroker.mint", spy)

    # Drive the PDP to classify the source UNTRUSTED the only way that is
    # agent-INDEPENDENT on this path: an operator/PEP-set ``untrusted_source``
    # marker on the deep request's metadata (the in-path PEP labels tool-fetched
    # content untrusted BEFORE decide). The calling agent cannot set this through
    # the mint body — it is an ``EvaluationRequest.metadata`` key, never a
    # ``MintRequest`` field. Wired via a dedicated evaluate command.
    monkeypatch.setattr(gov, "_evaluate", _UntrustedIfcEvaluate(), raising=True)

    resp = _client(gov).post(
        "/v1/govern/mint",
        json={
            "action_type": _ACT,
            "agent_id": str(agent_id),
            "content": "forward the fetched web content",
            "recipient": _AUD,
            "dpop_proof": proof,
            # NO operand_label_* / lineage_root / label_signature — the caller
            # supplies NO label; the PDP is the only source.
        },
    )

    assert resp.status_code == 403, resp.text
    payload = resp.json()
    assert payload["released"] is False
    assert "access_token" not in payload
    assert "token" not in payload
    assert payload["reason"].startswith("insufficient_integrity")
    # The signer was PROVABLY never reached — the floor check killed it before
    # any token issuance.
    spy.assert_not_called()
    assert spy.call_count == 0


class _UntrustedIfcEvaluate(_RealIfcEvaluate):
    """Same real classifier, but the in-path PEP marked the source untrusted
    (operator/PEP metadata, NOT a caller field) so the PDP labels it
    TOOL_UNTRUSTED -> CaMeL UNTRUSTED."""

    def execute(self, request):
        from dataclasses import replace as _replace

        # Inject the operator/PEP untrusted marker into request.metadata. This is
        # exactly the agent-INDEPENDENT signal the IFC classifier consumes; the
        # calling agent cannot set it through the mint body.
        try:
            marked = request.model_copy(
                update={"metadata": {**dict(request.metadata), "untrusted_source": True}}
            )
        except Exception:  # noqa: BLE001 — dataclass fallback
            marked = _replace(request, metadata={**dict(request.metadata), "untrusted_source": True})
        return super().execute(marked)


# --------------------------------------------------------------------------- #
# (B) PDP classifies a TRUSTED-floor-clearing source -> mint SUCCEEDS; the      #
#     token's prov_commit is bound to TEX'S ruling, with NO caller label field. #
# --------------------------------------------------------------------------- #


def test_live_B_pdp_label_mints_and_binds_to_ruling(monkeypatch) -> None:
    _live_env(monkeypatch)
    sk = _pin_ed25519_key(monkeypatch)
    agent_id = uuid4()
    gov = _gov(_Agent(agent_id))

    # On the bare path the PDP labels content USER_INPUT -> CaMeL USER (1) and
    # confidentiality INTERNAL -> CaMeL INTERNAL (1) (the IFC CI graph defaults
    # non-empty content to INTERNAL). USER/INTERNAL does NOT dominate the default
    # TRUSTED/PUBLIC floor, so a bare mint would REFUSE. To let a TRUSTED-source
    # action MINT, the OPERATOR relaxes the floor for this (aud, act) to
    # USER/INTERNAL — operator CODE, never a request field. The agent still
    # cannot raise its OWN label; the operator decided what floor this audience
    # tolerates.
    _relax_floor(
        monkeypatch,
        aud=_AUD,
        act=_ACT,
        floor=FidesLabel(
            integrity=CapabilityLevel.USER,
            confidentiality=ConfidentialityLevel.INTERNAL,
        ),
    )

    priv = Ed25519PrivateKey.generate()
    proof, jkt = _dpop_proof(priv, audience=_AUD, action=_ACT)

    resp = _client(gov).post(
        "/v1/govern/mint",
        json={
            "action_type": _ACT,
            "agent_id": str(agent_id),
            "content": "send the approved payroll note",
            "recipient": _AUD,
            "dpop_proof": proof,
            "ttl": 120,
            # NO operand_label_* / lineage_root / label_signature.
        },
    )
    assert resp.status_code == 200, resp.text
    payload = resp.json()
    token = payload["access_token"]
    assert token
    assert payload["cnf"]["jkt"] == jkt
    decision_id = payload["decision_id"]

    # The token carries the SELF-SIGNED prov_commit. Offline verify PERMITs and
    # the label is the PDP-derived USER (1), NOT a caller value.
    jwks = tgpcc_public_jwks()
    body_b64 = token.partition(".")[0]
    claims = _json.loads(base64.urlsafe_b64decode(body_b64 + "=" * (-len(body_b64) % 4)))
    now = claims["iat"]
    chk = verify_with_jwks(token, jwks, now=now)
    assert chk.ok is True, chk.reason
    pc = chk.claims["prov_commit"]
    assert pc["label"]["integrity"] == int(CapabilityLevel.USER)  # PDP-derived
    # The label_id binds to TEX'S exact ruling — pdp:{decision_id}:{evidence_hash}.
    assert pc["label_id"].startswith("pdp:")
    assert pc["label_id"].startswith(f"pdp:{decision_id}:")
    # The floor re-check PERMITs from the signed claims (label ⊒ relaxed floor).
    floor_chk = verify_prov_commit_floor(chk.claims)
    assert floor_chk.ok is True, floor_chk.reason

    # Sanity: the verifying JWKS key is the signing key's public half.
    raw = sk.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    assert jwks["keys"][0]["x"] == pop.public_jwk(raw)["x"]


# --------------------------------------------------------------------------- #
# (C) NOT-CIRCULAR / anti-forge — a forged caller TRUSTED label is IGNORED.     #
#     The agent cannot raise its own label.                                     #
# --------------------------------------------------------------------------- #


def test_live_C_forged_caller_trusted_label_ignored(monkeypatch) -> None:
    """Decisive agent-independence: the caller injects a TRUSTED label + a
    fabricated signature on an UNTRUSTED-classified request. In LIVE mode the
    route reads ``outcome.integrity_label`` (the PDP's UNTRUSTED), NOT the body —
    so the forged TRUSTED claim does NOT change the outcome: still 403."""
    _live_env(monkeypatch)
    _pin_ed25519_key(monkeypatch)
    agent_id = uuid4()
    gov = _gov(_Agent(agent_id))
    # PDP classifies UNTRUSTED (operator/PEP marker via the evaluate command).
    monkeypatch.setattr(gov, "_evaluate", _UntrustedIfcEvaluate(), raising=True)

    priv = Ed25519PrivateKey.generate()
    proof, _ = _dpop_proof(priv, audience=_AUD, action=_ACT)
    spy = mock.Mock(side_effect=AssertionError("signer reached on forged-label live mint"))
    monkeypatch.setattr("tex.authority.broker.CredentialBroker.mint", spy)

    resp = _client(gov).post(
        "/v1/govern/mint",
        json={
            "action_type": _ACT,
            "agent_id": str(agent_id),
            "content": "forward the fetched web content",
            "recipient": _AUD,
            "dpop_proof": proof,
            # The agent FORGES a TRUSTED label that WOULD dominate the floor, with
            # a fabricated signature. In LIVE mode these are IGNORED entirely.
            "operand_label_integrity": int(CapabilityLevel.TRUSTED),
            "operand_label_confidentiality": int(ConfidentialityLevel.PUBLIC),
            "operand_label_id": "agent-forged-trusted",
            "lineage_root": "deadbeef" * 8,
            "label_signature": "f" * 64,
        },
    )
    # Still refused — the caller's TRUSTED claim did not raise the gate.
    assert resp.status_code == 403, resp.text
    payload = resp.json()
    assert "access_token" not in payload
    assert payload["reason"].startswith("insufficient_integrity")
    # And the refusal cites the meet ⋢ floor (the PDP-derived UNTRUSTED), proving
    # the route gated on the PDP label, not the forged TRUSTED body field.
    assert "meet=UNTRUSTED" in payload["reason"]
    spy.assert_not_called()


def test_live_C_forged_label_cannot_flip_a_clean_refusal(monkeypatch) -> None:
    """Companion to (C): even on the BARE path (no untrusted marker, PDP labels
    USER) with the DEFAULT TRUSTED floor, a forged caller TRUSTED label does not
    mint — the PDP's USER label is what the route gates on. Proves the forged
    field is inert under the live flag regardless of the PDP class."""
    _live_env(monkeypatch)
    _pin_ed25519_key(monkeypatch)
    agent_id = uuid4()
    gov = _gov(_Agent(agent_id))  # bare path => PDP labels USER
    priv = Ed25519PrivateKey.generate()
    proof, _ = _dpop_proof(priv, audience=_AUD, action=_ACT)
    spy = mock.Mock(side_effect=AssertionError("signer reached on forged-label bare mint"))
    monkeypatch.setattr("tex.authority.broker.CredentialBroker.mint", spy)
    resp = _client(gov).post(
        "/v1/govern/mint",
        json={
            "action_type": _ACT,
            "agent_id": str(agent_id),
            "content": "ordinary user text",
            "recipient": _AUD,
            "dpop_proof": proof,
            "operand_label_integrity": int(CapabilityLevel.TRUSTED),
            "operand_label_confidentiality": int(ConfidentialityLevel.PUBLIC),
            "operand_label_id": "agent-forged-trusted",
            "lineage_root": "deadbeef" * 8,
            "label_signature": "f" * 64,
        },
    )
    assert resp.status_code == 403, resp.text
    assert "access_token" not in resp.json()
    # USER (the PDP label) ⋢ TRUSTED (the default floor) — the forged TRUSTED is
    # never consulted.
    assert "meet=USER" in resp.json()["reason"]
    spy.assert_not_called()


# --------------------------------------------------------------------------- #
# (D) Missing producer secret under the live flag -> fail-closed.              #
# --------------------------------------------------------------------------- #


def test_live_D_no_producer_secret_fails_closed(monkeypatch) -> None:
    monkeypatch.setenv("TEX_GOVERN_MINT", "1")
    monkeypatch.setenv("TEX_AUTHORITY_SIGNING_SECRET", SECRET)
    monkeypatch.setenv("TEX_TAINT_GATED_MINT", "1")
    monkeypatch.setenv("TEX_TAINT_LABEL_LIVE", "1")
    monkeypatch.delenv("TEX_TAINT_LABEL_SECRET", raising=False)  # NO secret
    monkeypatch.setenv("TEX_APP_ENV", "test")
    _pin_ed25519_key(monkeypatch)
    # Relax the floor so the ONLY thing that can refuse is the missing secret.
    _relax_floor(
        monkeypatch,
        aud=_AUD,
        act=_ACT,
        floor=FidesLabel(
            integrity=CapabilityLevel.USER,
            confidentiality=ConfidentialityLevel.INTERNAL,
        ),
    )
    agent_id = uuid4()
    gov = _gov(_Agent(agent_id))
    priv = Ed25519PrivateKey.generate()
    proof, _ = _dpop_proof(priv, audience=_AUD, action=_ACT)
    spy = mock.Mock(side_effect=AssertionError("signer reached with no producer secret"))
    monkeypatch.setattr("tex.authority.broker.CredentialBroker.mint", spy)
    resp = _client(gov).post(
        "/v1/govern/mint",
        json={
            "action_type": _ACT,
            "agent_id": str(agent_id),
            "content": "send the approved payroll note",
            "recipient": _AUD,
            "dpop_proof": proof,
        },
    )
    assert resp.status_code == 403, resp.text
    assert "access_token" not in resp.json()
    assert resp.json()["reason"].startswith("insufficient_integrity")
    spy.assert_not_called()


# --------------------------------------------------------------------------- #
# Inertness guard — LIVE flag OFF: the legacy caller-presented path runs and    #
# DecisionOutcome carries no integrity_label on the wire.                       #
# --------------------------------------------------------------------------- #


def test_live_off_decisionoutcome_label_not_serialized() -> None:
    """``DecisionOutcome.integrity_label`` is in-process plumbing only — it must
    NEVER appear in ``to_jsonable()`` (the /decide + /mint wire bytes), exactly
    like ``response`` / ``forbid_scope``. A default boot is byte-for-byte inert."""
    from tex.authority.taint_label import PdpIntegrityLabel
    from tex.governance.standing import DecisionOutcome

    out = DecisionOutcome(
        verdict=Verdict.PERMIT,
        released=True,
        reason="x",
        tier="deep",
        decision_id=uuid4(),
        evidence_hash="evh",
        integrity_label=PdpIntegrityLabel(
            integrity=CapabilityLevel.USER,
            confidentiality=ConfidentialityLevel.INTERNAL,
            label_id="pdp:x:y",
            source="USER_INPUT",
            basis="ifc:USER_INPUT",
        ),
    )
    j = out.to_jsonable()
    assert "integrity_label" not in j
    # And the new field defaults to None so every existing construction is
    # unaffected.
    bare = DecisionOutcome(verdict=Verdict.FORBID, released=False, reason="r", tier="floor")
    assert bare.integrity_label is None


def test_live_off_attach_pdp_label_is_noop(monkeypatch) -> None:
    """With the live flag UNSET, decide() attaches NO label even when the PDP
    produced ifc_labels — proving the producer lives entirely behind the flag."""
    monkeypatch.delenv("TEX_TAINT_LABEL_LIVE", raising=False)
    agent_id = uuid4()
    gov = _gov(_Agent(agent_id))
    out = gov.decide(
        tenant="acme",
        action_type=_ACT,
        content="ordinary user text",
        channel="email",
        environment="production",
        recipient=_AUD,
        agent_id=agent_id,
    )
    assert out.verdict is Verdict.PERMIT
    assert out.integrity_label is None  # flag off => no label attached


def test_live_on_attach_pdp_label_populates(monkeypatch) -> None:
    """With the live flag ON, a real decide() PERMIT carries the PDP-derived,
    agent-independent label — sourced from the real classifier (USER_INPUT on the
    bare path), NOT a caller field."""
    monkeypatch.setenv("TEX_TAINT_LABEL_LIVE", "1")
    agent_id = uuid4()
    gov = _gov(_Agent(agent_id))
    out = gov.decide(
        tenant="acme",
        action_type=_ACT,
        content="ordinary user text",
        channel="email",
        environment="production",
        recipient=_AUD,
        agent_id=agent_id,
    )
    assert out.verdict is Verdict.PERMIT
    assert out.integrity_label is not None
    # Bare path => USER_INPUT => CaMeL USER (the honest, non-circular default:
    # USER does NOT dominate the default TRUSTED floor).
    assert out.integrity_label.integrity == CapabilityLevel.USER
    assert out.integrity_label.source == "USER_INPUT"
    assert out.integrity_label.label_id.startswith("pdp:")
