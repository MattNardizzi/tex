from __future__ import annotations

from typing import Any, Protocol, cast, runtime_checkable
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field

from tex.api.auth import RequireScope, authenticate_request

from tex.api.schemas import (
    ActivatePolicyRequestDTO,
    ActivatePolicyResponseDTO,
    CalibratePolicyRequestDTO,
    CalibratePolicyResponseDTO,
    EvaluateRequestDTO,
    EvaluateResponseDTO,
    ExportBundleRequestDTO,
    ExportBundleResponseDTO,
    ReportOutcomeRequestDTO,
    ReportOutcomeResponseDTO,
)
from tex.commands.activate_policy import ActivatePolicyCommand
from tex.commands.calibrate_policy import CalibratePolicyCommand
from tex.commands.evaluate_action import EvaluateActionCommand
from tex.commands.export_bundle import ExportBundleCommand
from tex.commands.report_outcome import ReportOutcomeCommand
from tex.learning.drift import PolicyDriftMonitor, PolicyDriftReport


@runtime_checkable
class SupportsExecuteEvaluate(Protocol):
    def execute(self, request: Any) -> Any:
        """Executes one Tex evaluation request."""


@runtime_checkable
class SupportsExecuteOutcome(Protocol):
    def execute(self, outcome: Any) -> Any:
        """Executes one Tex outcome-reporting request."""


@runtime_checkable
class SupportsExecuteActivatePolicy(Protocol):
    def execute(self, version: str) -> Any:
        """Activates one policy version."""


@runtime_checkable
class SupportsExecuteCalibratePolicy(Protocol):
    def execute(
        self,
        *,
        source_policy_version: str | None = None,
        classifications: tuple[Any, ...] | list[Any],
        new_version: str | None = None,
        save: bool = False,
        activate: bool = False,
        metadata_updates: dict[str, object] | None = None,
    ) -> Any:
        """Runs one calibration pass."""


@runtime_checkable
class SupportsExportBundle(Protocol):
    def export_json(
        self,
        *,
        path: str,
        export_name: str = "tex-evidence-bundle",
        verify_chain: bool = True,
        indent: int = 2,
    ) -> Any:
        """Exports a full JSON evidence bundle."""

    def export_jsonl(
        self,
        *,
        path: str,
    ) -> Any:
        """Exports raw JSONL evidence records."""

    def export_filtered_json(
        self,
        *,
        path: str,
        record_type: str | None = None,
        decision_id: str | None = None,
        outcome_id: str | None = None,
        export_name: str = "tex-evidence-filtered-bundle",
        verify_chain: bool = False,
        indent: int = 2,
    ) -> Any:
        """Exports a filtered JSON evidence bundle."""


router = APIRouter(tags=["tex"])


@router.get(
    "/health",
    summary="Health check",
)
def health_check() -> dict[str, str]:
    """Simple liveness endpoint for local development and smoke testing."""
    return {"status": "ok"}


@router.post(
    "/evaluate",
    response_model=EvaluateResponseDTO,
    status_code=status.HTTP_200_OK,
    summary="Evaluate one action through Tex",
    dependencies=[Depends(RequireScope("decision:write"))],
)
def evaluate_action(
    payload: EvaluateRequestDTO,
    request: Request,
) -> EvaluateResponseDTO:
    """
    Evaluates one action request through Tex and returns the public response.
    """
    command = _get_evaluate_action_command(request)
    domain_request = payload.to_domain()

    try:
        result = command.execute(domain_request)
    except LookupError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(exc),
        ) from exc
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc
    except TypeError as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(exc),
        ) from exc

    return EvaluateResponseDTO.from_command_result(
        result,
        base_url=str(request.base_url).rstrip("/"),
    )


@router.get(
    "/decisions/{decision_id}/replay",
    status_code=status.HTTP_200_OK,
    summary="Replay a stored Tex decision for audit",
    dependencies=[Depends(RequireScope("decision:read"))],
)
def replay_decision(
    decision_id: UUID,
    request: Request,
) -> dict[str, Any]:
    """
    Return the durable Decision record for a prior evaluation.

    This is the audit surface: the verdict, confidence, scores, reasons,
    uncertainty flags, and full ASI findings as they were when the
    decision was made. Consumers can diff the stored decision against
    a re-run to detect model drift.
    """
    decision_store = _require_app_state_attr(request, "decision_store")
    store = cast(Any, decision_store)
    decision = store.get(decision_id)
    if decision is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"decision not found: {decision_id}",
        )
    return decision.model_dump(mode="json")


@router.get(
    "/decisions/{decision_id}/evidence-bundle",
    status_code=status.HTTP_200_OK,
    summary="Export the signed evidence bundle for a decision",
    dependencies=[Depends(RequireScope("evidence:read"))],
)
def evidence_bundle_for_decision(
    decision_id: UUID,
    request: Request,
) -> dict[str, Any]:
    """
    Return the hash-chained evidence bundle containing every record
    associated with a decision_id.

    The bundle is a *slice* of the global chain. To enable
    inclusion-proof verification against the parent chain, the bundle
    envelope carries ``prior_link_witness`` — the ``record_hash`` of
    the record immediately preceding the first record of the slice in
    the global JSONL chain (``None`` if the slice begins at the chain
    genesis). External verifiers reproduce this witness against their
    own copy of the chain to confirm continuity, the same way
    Certificate Transparency clients and Sigstore Rekor verifiers
    consume audit proofs.

    Until Thread 6 landed, this endpoint reported
    ``is_chain_valid: False`` on every single-record bundle that was
    not the global genesis, with the issue text "first record must
    not contain a previous_hash" (KNOWN_BUGS #5). The verifier was
    treating the slice's first record as if it were the chain genesis.
    The fix is the witness pattern below.
    """
    exporter = _require_app_state_attr(request, "evidence_exporter")
    exporter_obj = cast(Any, exporter)

    bundle = exporter_obj.build_slice_bundle(
        export_name=f"decision-{decision_id}",
        decision_id=decision_id,
    )

    if bundle.record_count == 0:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"no evidence records for decision: {decision_id}",
        )

    return bundle.to_dict()


class HumanResolutionRequest(BaseModel):
    """The named human act that resolves a held decision."""

    verdict: str = Field(
        description="Human verdict on the hold: 'approved', 'held', or 'refused'.",
    )
    resolved_by: str = Field(
        min_length=1,
        max_length=320,
        description="Identity of the human who resolved the hold (e.g. operator email).",
    )
    note: str | None = Field(
        default=None,
        max_length=2000,
        description="Optional auditor-facing note; no sensitive payload content.",
    )


@router.post(
    "/decisions/{decision_id}/seal",
    status_code=status.HTTP_201_CREATED,
    summary="Seal a held decision with a named human act",
    dependencies=[Depends(RequireScope("decision:write"))],
)
def seal_human_resolution(
    decision_id: UUID,
    body: HumanResolutionRequest,
    request: Request,
) -> dict[str, Any]:
    """
    Resolve a held (ABSTAIN) decision by a NAMED human act and seal it.

    A held decision is not approved by a spoken "yes" — it is sealed by a named
    human act the evidence layer can prove. This records the operator's
    approve / hold / refuse choice as its own hash-chained, post-quantum-signed
    evidence row, linked to the decision it resolves, and returns the anchor the
    operator walks away with: the record hash, the seal time, and the embedded
    signature (algorithm, key id, signed bytes, and the public key needed to
    verify the seal standalone).
    """
    decision_store = _require_app_state_attr(request, "decision_store")
    decision = cast(Any, decision_store).get(decision_id)
    if decision is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"decision not found: {decision_id}",
        )

    recorder = _require_app_state_attr(request, "evidence_recorder")

    # Link the seal to the decision's own most recent evidence record when one
    # exists, so the resolution points back at the thing it resolves.
    parent_hash: str | None = None
    try:
        exporter = getattr(request.app.state, "evidence_exporter", None)
        if exporter is not None:
            bundle = cast(Any, exporter).build_slice_bundle(
                export_name=f"decision-{decision_id}",
                decision_id=decision_id,
            )
            records = getattr(bundle, "records", None) or []
            if records:
                parent_hash = getattr(records[-1], "record_hash", None)
    except Exception:  # noqa: BLE001 — linkage is best-effort, never blocks the seal
        parent_hash = None

    try:
        record = cast(Any, recorder).record_human_resolution(
            decision,
            verdict=body.verdict,
            resolved_by=body.resolved_by,
            note=body.note,
            parent_evidence_hash=parent_hash,
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(exc),
        ) from exc

    import json as _json

    payload = _json.loads(record.payload_json)
    pq = payload.get("pq_signature")
    signature_block: dict[str, Any] | None = None
    if isinstance(pq, dict):
        # Surface the seal so the operator (and any third party) can verify it.
        signature_block = {
            "algorithm": pq.get("algorithm"),
            "key_id": pq.get("key_id"),
            "signature_b64": pq.get("signature_b64"),
            "public_key_b64": pq.get("public_key_b64"),
            "signed_at": pq.get("signed_at"),
            "post_quantum": "ml-dsa" in str(pq.get("algorithm", "")),
        }

    return {
        "decision_id": str(decision_id),
        "human_verdict": payload.get("human_verdict"),
        "resolved_by": payload.get("resolved_by"),
        "sealed_at": payload.get("resolved_at"),
        "evidence_id": str(record.evidence_id),
        "anchor_sha256": record.record_hash,
        "previous_hash": record.previous_hash,
        "pq_signature": signature_block,
    }


@router.get(
    "/policies/{policy_version}/drift",
    status_code=status.HTTP_200_OK,
    summary="Policy-drift report for a policy version",
    response_model=PolicyDriftReport,
    dependencies=[Depends(RequireScope("policy:read"))],
)
def policy_drift(
    policy_version: str,
    request: Request,
    window_size: int = 50,
) -> PolicyDriftReport:
    """
    Compare verdict distribution across two recent windows of decisions
    on the given policy version.

    Surfaces abstain-rate climb/fall, permit-rate shifts, and
    forbid-rate shifts so operators can see when a policy is drifting
    before it shows up as customer pain.
    """
    decision_store = _require_app_state_attr(request, "decision_store")
    monitor = PolicyDriftMonitor(cast(Any, decision_store))
    try:
        return monitor.report(
            policy_version=policy_version,
            window_size=window_size,
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc


@router.post(
    "/outcomes",
    response_model=ReportOutcomeResponseDTO,
    status_code=status.HTTP_200_OK,
    summary="Report an observed outcome for a prior Tex decision",
    dependencies=[Depends(RequireScope("outcome:write"))],
)
def report_outcome(
    payload: ReportOutcomeRequestDTO,
    request: Request,
) -> ReportOutcomeResponseDTO:
    """
    Records what happened after a prior Tex decision and returns the resulting
    outcome classification.
    """
    command = _get_report_outcome_command(request)
    outcome = payload.to_domain()

    try:
        result = command.execute(outcome)
    except LookupError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(exc),
        ) from exc
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc
    except TypeError as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(exc),
        ) from exc

    return ReportOutcomeResponseDTO.from_command_result(result)


@router.post(
    "/policies/activate",
    response_model=ActivatePolicyResponseDTO,
    status_code=status.HTTP_200_OK,
    summary="Activate a stored policy version",
    dependencies=[Depends(RequireScope("policy:write"))],
)
def activate_policy(
    payload: ActivatePolicyRequestDTO,
    request: Request,
) -> ActivatePolicyResponseDTO:
    """
    Activates a stored policy version and returns the previous/next active state.
    """
    command = _get_activate_policy_command(request)

    try:
        result = command.execute(payload.version)
    except LookupError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(exc),
        ) from exc
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc
    except TypeError as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(exc),
        ) from exc

    return ActivatePolicyResponseDTO.from_command_result(result)


@router.post(
    "/policies/calibrate",
    response_model=CalibratePolicyResponseDTO,
    status_code=status.HTTP_200_OK,
    summary="Run a calibration pass against classified outcomes",
    dependencies=[Depends(RequireScope("policy:write"))],
)
def calibrate_policy(
    payload: CalibratePolicyRequestDTO,
    request: Request,
) -> CalibratePolicyResponseDTO:
    """
    Runs one calibration pass from already-classified outcomes.

    This route keeps calibration explicit. It does not search the full system
    for candidate outcomes on the caller's behalf.
    """
    command = _get_calibrate_policy_command(request)

    try:
        result = command.execute(
            source_policy_version=payload.source_policy_version,
            classifications=payload.to_domain_classifications(),
            new_version=payload.new_version,
            save=payload.save,
            activate=payload.activate,
            metadata_updates=payload.metadata_updates,
        )
    except LookupError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(exc),
        ) from exc
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc
    except TypeError as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(exc),
        ) from exc

    return CalibratePolicyResponseDTO.from_command_result(result)


@router.post(
    "/evidence/export",
    response_model=ExportBundleResponseDTO,
    status_code=status.HTTP_200_OK,
    summary="Export Tex evidence artifacts",
    dependencies=[Depends(RequireScope("evidence:read"))],
)
def export_bundle(
    payload: ExportBundleRequestDTO,
    request: Request,
) -> ExportBundleResponseDTO:
    """
    Exports Tex evidence artifacts in either wrapped JSON or raw JSONL form.
    """
    command = _get_export_bundle_command(request)

    try:
        if payload.export_format == "jsonl":
            result = command.export_jsonl(path=payload.path)
        elif (
            payload.record_type is not None
            or payload.decision_id is not None
            or payload.outcome_id is not None
        ):
            result = command.export_filtered_json(
                path=payload.path,
                record_type=payload.record_type,
                decision_id=payload.decision_id,
                outcome_id=payload.outcome_id,
                export_name=payload.export_name,
                verify_chain=payload.verify_chain,
                indent=payload.indent,
            )
        else:
            result = command.export_json(
                path=payload.path,
                export_name=payload.export_name,
                verify_chain=payload.verify_chain,
                indent=payload.indent,
            )
    except LookupError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(exc),
        ) from exc
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc
    except TypeError as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(exc),
        ) from exc
    except OSError as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"failed to export evidence bundle: {exc}",
        ) from exc

    return ExportBundleResponseDTO.from_command_result(result)


def build_api_router() -> APIRouter:
    """Convenience constructor for Tex's FastAPI router."""
    return router


def _get_evaluate_action_command(request: Request) -> SupportsExecuteEvaluate:
    command = _require_app_state_attr(request, "evaluate_action_command")
    _assert_protocol(
        value=command,
        protocol=SupportsExecuteEvaluate,
        attribute_name="evaluate_action_command",
    )
    return cast(SupportsExecuteEvaluate, command)


def _get_report_outcome_command(request: Request) -> SupportsExecuteOutcome:
    command = _require_app_state_attr(request, "report_outcome_command")
    _assert_protocol(
        value=command,
        protocol=SupportsExecuteOutcome,
        attribute_name="report_outcome_command",
    )
    return cast(SupportsExecuteOutcome, command)


def _get_activate_policy_command(
    request: Request,
) -> SupportsExecuteActivatePolicy:
    command = _require_app_state_attr(request, "activate_policy_command")
    _assert_protocol(
        value=command,
        protocol=SupportsExecuteActivatePolicy,
        attribute_name="activate_policy_command",
    )
    return cast(SupportsExecuteActivatePolicy, command)


def _get_calibrate_policy_command(
    request: Request,
) -> SupportsExecuteCalibratePolicy:
    command = _require_app_state_attr(request, "calibrate_policy_command")
    _assert_protocol(
        value=command,
        protocol=SupportsExecuteCalibratePolicy,
        attribute_name="calibrate_policy_command",
    )
    return cast(SupportsExecuteCalibratePolicy, command)


def _get_export_bundle_command(request: Request) -> SupportsExportBundle:
    command = _require_app_state_attr(request, "export_bundle_command")
    _assert_protocol(
        value=command,
        protocol=SupportsExportBundle,
        attribute_name="export_bundle_command",
    )
    return cast(SupportsExportBundle, command)


def _require_app_state_attr(request: Request, name: str) -> object:
    if not hasattr(request.app.state, name):
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=(
                f"Tex app is missing required state dependency: {name}. "
                "Initialize the command stack before serving requests."
            ),
        )
    return getattr(request.app.state, name)


def _assert_protocol(
    *,
    value: object,
    protocol: type[Protocol],
    attribute_name: str,
) -> None:
    if not isinstance(value, protocol):
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=(
                f"Tex app state dependency {attribute_name!r} does not satisfy "
                f"the required interface: {protocol.__name__}"
            ),
        )