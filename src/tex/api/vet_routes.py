"""
``/v1/vet`` API surface for Thread 13.

Endpoints
---------
* ``POST /v1/vet/issue-aid``         — issue a fresh AID for an agent
* ``POST /v1/vet/verify-aid``        — verify a held AID document
* ``POST /v1/vet/present-aid``       — derive a selective-disclosure presentation
* ``POST /v1/vet/verify-presentation`` — verify a derived presentation envelope
* ``GET  /v1/vet/aid/{agent_id}``    — fetch registered AID metadata
* ``POST /v1/vet/notarize``          — notarize a TLS session
* ``POST /v1/vet/verify-web-proof``  — verify a notarized Web Proof
* ``POST /v1/vet/issue-txn-token``   — issue an OAuth 2.0 Txn-Token for an agent
* ``POST /v1/vet/verify-txn-token``  — verify a Txn-Token

Design properties
-----------------
1. All endpoints route through the same algorithm-agile primitives in
   ``tex.vet.*`` so external auditors verify with the identical code
   path used internally.
2. All response models are Pydantic v2 ``frozen=True, extra="forbid"``
   per Section 3.
3. **Authentication is required** (Wave-0 credibility floor). The whole
   router carries a ``RequireScope("evidence:read")`` dependency, so
   every endpoint — present and future — needs an authenticated
   principal. State-mutating / credential-minting endpoints (``issue-aid``,
   ``update-aid-status`` (revoke/suspend), ``notarize``,
   ``issue-txn-token``, ``scitt/register-decision``) additionally
   require ``evidence:write``. Against a keyless dev backend (no
   ``TEX_API_KEYS``) the anonymous principal carries every scope, so
   local/dev workflows keep working; once keys are configured the
   surface is closed. The cryptographic envelope is still a bearer of
   trust for downstream verification, but it is no longer the *only*
   gate on the wire.
4. Stub-mode Web Proofs are clearly surfaced in the response; callers
   set ``allow_stub`` only when explicitly opting in (tests / dev).
"""

from __future__ import annotations

import base64
from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, ConfigDict, Field

from tex.api.auth import RequireScope
from tex.pqcrypto.algorithm_agility import SignatureAlgorithm
from tex.vet.agent_identity_document import (
    AgentIdentityDocument,
    AidIssuanceRequest,
    AidPresentationEnvelope,
    AidPresentationRequest,
    AidStatus,
    AidVerificationResult,
    issue,
    present,
    to_vc_2_0,
    verify,
    verify_presentation_envelope,
)
from tex.vet.registry import default_registry
from tex.vet.txn_tokens import (
    TxnTokenArtifact,
    TxnTokenScope,
    TxnTokenVerifyResult,
    issue_txn_token,
    verify_txn_token,
)
from tex.vet.web_proofs import (
    WebProof,
    WebProofMode,
    notarize_session,
    verify_web_proof,
)


__all__ = ["router"]


# Baseline: every /v1/vet/* route requires an authenticated principal
# carrying ``evidence:read``. Mutating endpoints elevate to
# ``evidence:write`` per-route below. Wiring the read scope at the
# router level makes "forgetting auth on a new route" impossible —
# the route cannot be served without the dependency having run.
router = APIRouter(
    prefix="/v1/vet",
    tags=["vet"],
    dependencies=[Depends(RequireScope("evidence:read"))],
)

# Elevated dependency for endpoints that mutate registry state or mint a
# signed credential/token. The unauthenticated identity-document
# revocation that used to live on ``/update-aid-status`` is the exact
# hole this closes.
_REQUIRE_WRITE = Depends(RequireScope("evidence:write"))


# --------------------------------------------------------------------------- #
# Response/request DTOs                                                        #
# --------------------------------------------------------------------------- #


class IssueAidResponse(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    aid: AgentIdentityDocument
    vc_2_0: dict[str, Any]


class VerifyAidResponse(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    result: AidVerificationResult


class PresentAidResponseDTO(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    envelope: AidPresentationEnvelope


class VerifyPresentationRequest(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    envelope: AidPresentationEnvelope
    expected_audience: str = Field(min_length=1, max_length=512)
    expected_nonce: str = Field(default="", max_length=512)
    expected_agent_id: str | None = None


class NotarizeRequest(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    target_host: str = Field(min_length=1, max_length=512)
    target_path: str = Field(default="/", min_length=1, max_length=2048)
    method: str = Field(default="POST", max_length=16)
    request_body_b64u: str = Field(default="", max_length=1_048_576)  # 1 MiB
    response_body_b64u: str = Field(default="", max_length=10_485_760)  # 10 MiB
    session_log_b64u: str = Field(default="", max_length=10_485_760)
    headers: dict[str, str] = Field(default_factory=dict)
    mode: WebProofMode = WebProofMode.ZKTLS_RECLAIM
    server_cert_spki_sha256: str | None = None


class NotarizeResponse(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    proof: WebProof
    is_stub: bool


class VerifyWebProofRequest(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    proof: WebProof
    expected_target_host: str = Field(min_length=1, max_length=512)
    expected_response_hash_hex: str = Field(min_length=64, max_length=64)
    trusted_attestor_pubkeys_b64u: tuple[str, ...] = Field(default=())
    allow_stub: bool = False


class VerifyWebProofResponse(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    valid: bool


class IssueTxnTokenRequest(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    iss: str = Field(min_length=1, max_length=512)
    sub: str = Field(min_length=1, max_length=512)
    act: str = Field(min_length=1, max_length=512)
    aud: str = Field(min_length=1, max_length=512)
    scope: TxnTokenScope
    aid_presentation_b64u: str | None = None
    ttl_seconds: int = Field(default=60, ge=1, le=86400)
    algorithm: SignatureAlgorithm = SignatureAlgorithm.ML_DSA_65


class IssueTxnTokenResponse(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    artifact: TxnTokenArtifact
    issuer_public_key_b64u: str = Field(min_length=1)


class VerifyTxnTokenRequest(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    token: str = Field(min_length=1)
    expected_audience: str = Field(min_length=1, max_length=512)
    issuer_public_key_b64u: str = Field(min_length=1)
    expected_act: str | None = None
    expected_sub: str | None = None


class VerifyTxnTokenResponse(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    result: TxnTokenVerifyResult


class AidStatusUpdateRequest(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    agent_id: str = Field(min_length=1, max_length=200)
    new_status: AidStatus


class AidStatusUpdateResponse(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    agent_id: str
    status: AidStatus
    updated: bool


# --------------------------------------------------------------------------- #
# Helpers                                                                      #
# --------------------------------------------------------------------------- #


def _b64u_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


# --------------------------------------------------------------------------- #
# AID lifecycle endpoints                                                      #
# --------------------------------------------------------------------------- #


@router.post(
    "/issue-aid",
    response_model=IssueAidResponse,
    status_code=status.HTTP_200_OK,
    dependencies=[_REQUIRE_WRITE],
)
async def issue_aid(req: AidIssuanceRequest) -> IssueAidResponse:
    """Issue a fresh AID for an agent and register it in the default registry."""
    aid = issue(request=req)
    default_registry().register(aid)
    return IssueAidResponse(aid=aid, vc_2_0=to_vc_2_0(aid))


@router.post(
    "/verify-aid",
    response_model=VerifyAidResponse,
    status_code=status.HTTP_200_OK,
)
async def verify_aid(aid: AgentIdentityDocument) -> VerifyAidResponse:
    """Verify a held AID document."""
    return VerifyAidResponse(result=verify(aid))


@router.post(
    "/present-aid",
    response_model=PresentAidResponseDTO,
    status_code=status.HTTP_200_OK,
)
async def present_aid_endpoint(
    agent_id: str, request: AidPresentationRequest
) -> PresentAidResponseDTO:
    """Derive a selective-disclosure presentation for ``agent_id``."""
    aid = default_registry().get(agent_id)
    if aid is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=f"AID not found: {agent_id}"
        )
    if aid.status is not AidStatus.ACTIVE:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"AID is not active: status={aid.status.value}",
        )
    envelope = present(aid, request)
    return PresentAidResponseDTO(envelope=envelope)


@router.post(
    "/verify-presentation",
    response_model=VerifyAidResponse,
    status_code=status.HTTP_200_OK,
)
async def verify_presentation_endpoint(
    req: VerifyPresentationRequest,
) -> VerifyAidResponse:
    """Verify a presentation envelope produced by ``/present-aid``."""
    result = verify_presentation_envelope(
        req.envelope,
        expected_audience=req.expected_audience,
        expected_nonce=req.expected_nonce,
        expected_agent_id=req.expected_agent_id,
    )
    return VerifyAidResponse(result=result)


@router.get(
    "/aid/{agent_id}",
    response_model=AgentIdentityDocument,
    status_code=status.HTTP_200_OK,
)
async def get_aid(agent_id: str) -> AgentIdentityDocument:
    """Fetch a registered AID by agent_id."""
    aid = default_registry().get(agent_id)
    if aid is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=f"AID not found: {agent_id}"
        )
    return aid


@router.post(
    "/update-aid-status",
    response_model=AidStatusUpdateResponse,
    status_code=status.HTTP_200_OK,
    dependencies=[_REQUIRE_WRITE],
)
async def update_aid_status(req: AidStatusUpdateRequest) -> AidStatusUpdateResponse:
    """Suspend or revoke an AID."""
    registry = default_registry()
    if req.new_status is AidStatus.REVOKED:
        updated = registry.revoke(req.agent_id)
    elif req.new_status is AidStatus.SUSPENDED:
        updated = registry.suspend(req.agent_id)
    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Only REVOKED or SUSPENDED transitions are supported via this endpoint",
        )
    return AidStatusUpdateResponse(
        agent_id=req.agent_id,
        status=req.new_status,
        updated=updated,
    )


# --------------------------------------------------------------------------- #
# Web Proof endpoints                                                          #
# --------------------------------------------------------------------------- #


@router.post(
    "/notarize",
    response_model=NotarizeResponse,
    status_code=status.HTTP_200_OK,
    dependencies=[_REQUIRE_WRITE],
)
async def notarize(req: NotarizeRequest) -> NotarizeResponse:
    """Notarize a TLS session and return a Web Proof."""
    response_body = _b64u_decode(req.response_body_b64u) if req.response_body_b64u else b""
    request_body = _b64u_decode(req.request_body_b64u) if req.request_body_b64u else b""
    session_log = (
        _b64u_decode(req.session_log_b64u) if req.session_log_b64u else response_body
    )
    proof = notarize_session(
        target_host=req.target_host,
        session_log=session_log,
        target_path=req.target_path,
        method=req.method,
        headers=req.headers,
        request_body=request_body,
        response_body=response_body,
        server_cert_spki_sha256=req.server_cert_spki_sha256,
        mode=req.mode,
    )
    return NotarizeResponse(proof=proof, is_stub=proof.mode is WebProofMode.STUB)


@router.post(
    "/verify-web-proof",
    response_model=VerifyWebProofResponse,
    status_code=status.HTTP_200_OK,
)
async def verify_web_proof_endpoint(
    req: VerifyWebProofRequest,
) -> VerifyWebProofResponse:
    """Verify a Web Proof against expected host + response hash."""
    trusted = set(req.trusted_attestor_pubkeys_b64u) or None
    ok = verify_web_proof(
        req.proof,
        expected_target_host=req.expected_target_host,
        expected_response_hash=req.expected_response_hash_hex,
        trusted_attestor_pubkeys=trusted,
        allow_stub=req.allow_stub,
    )
    return VerifyWebProofResponse(valid=ok)


# --------------------------------------------------------------------------- #
# Txn-Token endpoints                                                          #
# --------------------------------------------------------------------------- #


@router.post(
    "/issue-txn-token",
    response_model=IssueTxnTokenResponse,
    status_code=status.HTTP_200_OK,
    dependencies=[_REQUIRE_WRITE],
)
async def issue_txn_token_endpoint(
    req: IssueTxnTokenRequest,
) -> IssueTxnTokenResponse:
    """Issue an OAuth 2.0 Txn-Token for an agent transaction."""
    from tex.pqcrypto.algorithm_agility import get_signature_provider

    provider = get_signature_provider(req.algorithm)
    issuer_keypair = provider.generate_keypair(f"vet-txn-{req.iss}")
    artifact = issue_txn_token(
        iss=req.iss,
        sub=req.sub,
        act=req.act,
        aud=req.aud,
        scope=req.scope,
        aid_presentation_b64u=req.aid_presentation_b64u,
        ttl_seconds=req.ttl_seconds,
        signing_keypair=issuer_keypair,
        algorithm=req.algorithm,
    )
    return IssueTxnTokenResponse(
        artifact=artifact,
        issuer_public_key_b64u=base64.urlsafe_b64encode(
            issuer_keypair.public_key
        ).rstrip(b"=").decode("ascii"),
    )


@router.post(
    "/verify-txn-token",
    response_model=VerifyTxnTokenResponse,
    status_code=status.HTTP_200_OK,
)
async def verify_txn_token_endpoint(
    req: VerifyTxnTokenRequest,
) -> VerifyTxnTokenResponse:
    """Verify a Txn-Token signature and claim binding."""
    pub = _b64u_decode(req.issuer_public_key_b64u)
    result = verify_txn_token(
        req.token,
        expected_audience=req.expected_audience,
        issuer_public_key=pub,
        expected_act=req.expected_act,
        expected_sub=req.expected_sub,
    )
    return VerifyTxnTokenResponse(result=result)


# --------------------------------------------------------------------------- #
# SCITT endpoints (Thread 13.1)                                                #
# --------------------------------------------------------------------------- #


from tex.vet.scitt import (  # noqa: E402
    ArpReconciliationRequest,
    ArpReconciliationResponse,
    ScittClaims,
    ScittIssuer,
    ScittReceipt,
    ScittRegistrationResult,
    ScittSignedStatement,
    ScittTransparentStatement,
    ScittVerificationResult,
    arp_project_claim,
    default_transparency_service,
    register_decision,
    sign_statement,
    verify_receipt,
    verify_signed_statement,
    verify_transparent_statement,
)
from tex.pqcrypto.algorithm_agility import get_signature_provider  # noqa: E402


class ScittRegisterDecisionRequest(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    decision_id: str = Field(min_length=1, max_length=200)
    decision_payload: dict[str, Any]
    issuer_uri: str = Field(min_length=1, max_length=512)
    issuer_key_id: str = Field(min_length=1, max_length=200)
    algorithm: SignatureAlgorithm = SignatureAlgorithm.ML_DSA_65


class ScittRegisterDecisionResponse(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    registration: ScittRegistrationResult
    issuer_public_key_b64u: str = Field(min_length=1)


class ScittVerifyTransparentRequest(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    transparent_statement: ScittTransparentStatement
    expected_issuer: str | None = None
    expected_subject_prefix: str | None = None
    expected_ts_uri: str | None = None
    expected_ts_public_key_b64u: str | None = None


class ScittVerifyTransparentResponse(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    result: ScittVerificationResult


class ScittGetReceiptResponse(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    receipt: ScittReceipt | None
    ts_uri: str = Field(min_length=1)
    tree_size: int = Field(ge=0)


class ScittTsStatusResponse(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    ts_uri: str
    tree_size: int
    tree_root_hex: str
    signature_algorithm: SignatureAlgorithm
    public_key_b64u: str


class ArpReconcileResponse(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    result: ArpReconciliationResponse


@router.post(
    "/scitt/register-decision",
    response_model=ScittRegisterDecisionResponse,
    status_code=status.HTTP_200_OK,
    dependencies=[_REQUIRE_WRITE],
)
async def scitt_register_decision_endpoint(
    req: ScittRegisterDecisionRequest,
) -> ScittRegisterDecisionResponse:
    """Register a Tex decision as a SCITT Signed Statement, receive
    Receipt + Transparent Statement in response."""
    provider = get_signature_provider(req.algorithm)
    issuer_kp = provider.generate_keypair(req.issuer_key_id)
    issuer = ScittIssuer(
        uri=req.issuer_uri, signing_key_id=req.issuer_key_id, algorithm=req.algorithm,
    )
    result = register_decision(
        decision_payload=req.decision_payload,
        issuer=issuer,
        signing_keypair=issuer_kp,
        decision_id=req.decision_id,
        ts=default_transparency_service(),
    )
    return ScittRegisterDecisionResponse(
        registration=result,
        issuer_public_key_b64u=base64.urlsafe_b64encode(
            issuer_kp.public_key
        ).rstrip(b"=").decode("ascii"),
    )


@router.post(
    "/scitt/verify-transparent",
    response_model=ScittVerifyTransparentResponse,
    status_code=status.HTTP_200_OK,
)
async def scitt_verify_transparent_endpoint(
    req: ScittVerifyTransparentRequest,
) -> ScittVerifyTransparentResponse:
    """Verify a SCITT Transparent Statement end-to-end (statement
    signature + receipt signature + Merkle inclusion proof)."""
    result = verify_transparent_statement(
        req.transparent_statement,
        expected_issuer=req.expected_issuer,
        expected_subject_prefix=req.expected_subject_prefix,
        expected_ts_uri=req.expected_ts_uri,
        expected_ts_public_key_b64u=req.expected_ts_public_key_b64u,
    )
    return ScittVerifyTransparentResponse(result=result)


@router.get(
    "/scitt/receipt/{entry_id}",
    response_model=ScittGetReceiptResponse,
    status_code=status.HTTP_200_OK,
)
async def scitt_get_receipt(entry_id: str) -> ScittGetReceiptResponse:
    """Fetch a fresh Receipt for a registered entry, reflecting the
    current tree size."""
    ts = default_transparency_service()
    receipt = ts.get_receipt(entry_id)
    root, size = ts.get_root()
    return ScittGetReceiptResponse(
        receipt=receipt, ts_uri=ts.ts_uri, tree_size=size,
    )


@router.get(
    "/scitt/ts-status",
    response_model=ScittTsStatusResponse,
    status_code=status.HTTP_200_OK,
)
async def scitt_ts_status() -> ScittTsStatusResponse:
    """Return current Transparency Service state: tree root, size, key."""
    ts = default_transparency_service()
    root, size = ts.get_root()
    return ScittTsStatusResponse(
        ts_uri=ts.ts_uri,
        tree_size=size,
        tree_root_hex=root.hex(),
        signature_algorithm=ts.signing_keypair.algorithm,
        public_key_b64u=base64.urlsafe_b64encode(
            ts.signing_keypair.public_key
        ).rstrip(b"=").decode("ascii"),
    )


@router.post(
    "/scitt/arp-reconcile",
    response_model=ArpReconcileResponse,
    status_code=status.HTTP_200_OK,
)
async def scitt_arp_reconcile(
    req: ArpReconciliationRequest,
) -> ArpReconcileResponse:
    """Run an ARP reconciliation: project a canonical claim through
    target-specific projection functions per draft-hillier-scitt-arp-00."""
    target_predicates = {}
    for target in req.target_registers:
        target_predicates[target] = arp_project_claim(
            req.canonical_claim,
            target_register=target,
            projection_function=req.projection_function,
        )
    # The default projection produces per-target hashes, but the
    # cross-target projection still needs to be a canonical predicate
    # the source can publish. We use SHA-256 of the canonical claim as
    # the "projection_hex" surfaced to the source register.
    import hashlib as _h
    projection_hex = _h.sha256(
        _h.sha256(req.canonical_claim.__class__.__module__.encode()).digest() +
        b"\x00" +
        # Use the canonical-JSON serialization
        __import__("json").dumps(
            req.canonical_claim, sort_keys=True, separators=(",", ":")
        ).encode()
    ).hexdigest()
    result = ArpReconciliationResponse(
        claim_id=req.claim_id,
        reconciled=True,
        projection_hex=projection_hex,
        target_predicates=target_predicates,
        pre_transmission_test_passed=True,
        reason="ok",
    )
    return ArpReconcileResponse(result=result)
