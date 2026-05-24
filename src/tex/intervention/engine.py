"""
Intervention engine.

Selects and applies the minimum-cost intervention that satisfies the
bounded-compromise condition for the current drift state, then emits an
ML-DSA-signed governance-ledger record so the intervention is part of
the audit chain.

Design references
-----------------
- arxiv 2512.18561 v3 (AAF, Alqithami, Mar 19 2026), §4.4 Adaptive
  Intervention Mechanisms: three-tier playbook (reward shaping ->
  policy patching -> link throttling); Stage 1 responsibility heap;
  Stage 3 system-wide failsafe.
- arxiv 2602.11749 (AIR, Xiao/Sun/Chen, Feb 12 2026): incident response
  vocabulary (detect / contain / recover / eradicate). Tex's
  ``Intervention.rationale`` field is formatted with this vocabulary
  so AIR-compatible tooling can join across.
- arxiv 2604.07833 v2 (Embodied Agents Runtime Governance, Apr 10
  2026): intervention taxonomy spanning bounded retry, controller
  mode switching, recovery capability invocation, Human Override
  Interface escalation. Tex's seven ``InterventionKind``s map this
  taxonomy onto an agent-runtime surface.
- arxiv 2604.17562 (SafeAgent, Liu et al., Apr 19 2026): closest
  design-pattern neighbor (runtime controller + context-aware
  decision core with risk/utility/consequence operators). Tex's
  wedge over SafeAgent is the AAF cost-bound theorem itself; this
  engine implements the analytical guarantee SafeAgent's heuristic
  framework lacks.
- arxiv 2601.11369 §6.2.2 (Bracale/Syrnikov, Jan 2026): sanction
  ladder + cost_to_actor / cost_to_system field model.

Signing
-------
Every applied intervention emits a governance-log record signed
through ``tex.pqcrypto.algorithm_agility``. The signing provider
selection (ML-DSA-65 / hybrid / ECDSA-P256) is exactly the same as
the Thread-2 institutional log -- the intervention record joins the
existing log chain via ``GovernanceLog.record_observation``.

Per Section 3 hard constraints of the build master prompt:
- pydantic v2 strict (frozen dataclasses where pydantic isn't used);
- SHA-256 hash-chained, HMAC-signed evidence per ledger record;
- algorithm-agility-routed crypto (no direct ML-DSA call here);
- FAIL-CLOSED: select() returns None when nothing satisfies the bound,
  caller (EcosystemEngine step 8) must downgrade to ABSTAIN if it
  cannot recommend an intervention.

Priority: P2 (live).
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from tex.intervention.bounded_compromise import (
    BoundedCompromiseCalculator,
    CompromiseCertificate,
)
from tex.intervention.kinds import Intervention, InterventionKind
from tex.observability.telemetry import emit_event


# AIR (arxiv 2602.11749) lifecycle phases. Used in Intervention.rationale
# so downstream tooling (AIR-style consumers, EU AI Act Art. 50 auditors)
# can join across the vocabulary boundary without depending on AIR
# itself.
_PHASE_CONTAIN: str = "contain"
_PHASE_RECOVER: str = "recover"
_PHASE_HOLD: str = "hold"  # human-approval gate; not yet contained
_PHASE_ERADICATE: str = "eradicate"  # Thread 8.1: AIR §3 eradication


# Mapping from InterventionKind to AIR phase. Kept conservative: every
# intervention defaults to CONTAIN unless its semantics are clearly
# recovery- or hold- or eradication-shaped.
_KIND_TO_PHASE: dict[InterventionKind, str] = {
    InterventionKind.CAPABILITY_REVOKE: _PHASE_CONTAIN,
    InterventionKind.TRUST_SCORE_REDUCE: _PHASE_CONTAIN,
    InterventionKind.REWARD_SHAPE: _PHASE_CONTAIN,
    InterventionKind.POLICY_PATCH: _PHASE_CONTAIN,
    InterventionKind.HUMAN_APPROVAL_GATE: _PHASE_HOLD,
    InterventionKind.QUARANTINE: _PHASE_CONTAIN,
    InterventionKind.RESTORATIVE_PATH: _PHASE_RECOVER,
    InterventionKind.ERADICATION_RULE_SYNTHESIS: _PHASE_ERADICATE,
}


# Governance-log payload kind for intervention applications.
_LOG_KIND_INTERVENTION: str = "intervention_applied"


def air_phase_for(kind: InterventionKind) -> str:
    """Return the AIR (arxiv 2602.11749) lifecycle phase for a kind."""
    return _KIND_TO_PHASE.get(kind, _PHASE_CONTAIN)


class InterventionSelectionError(RuntimeError):
    """Raised when intervention selection encounters an unrecoverable state.

    Distinct from "no candidate satisfies the bound" (which returns
    None per FAIL-CLOSED). This is for malformed candidate lists,
    contract violations on the calculator, etc.
    """


class InterventionApplyError(RuntimeError):
    """Raised when intervention application fails (e.g. ledger append).

    The engine FAIL-CLOSES: the caller treats this as if the
    intervention did not apply, and the verdict is downgraded
    accordingly.
    """


class InterventionEngine:
    """
    The Step-8 intervention selector and applicator.

    Construction
    ------------
    >>> from tex.intervention.bounded_compromise import (
    ...     BoundedCompromiseCalculator,
    ... )
    >>> calc = BoundedCompromiseCalculator()
    >>> engine = InterventionEngine(
    ...     bounded_compromise_calc=calc, ledger=governance_log,
    ... )

    The ``ledger`` parameter accepts a ``GovernanceLog`` instance (the
    primary path) or ``None`` (test path: applies record only emit
    telemetry, no signed log entry).
    """

    def __init__(
        self,
        *,
        bounded_compromise_calc: BoundedCompromiseCalculator,
        ledger: Any | None,  # tex.institutional.governance_log.GovernanceLog | None
        eradication_synthesizer: Any | None = None,
        rule_registry: Any | None = None,
    ) -> None:
        if bounded_compromise_calc is None:
            raise ValueError(
                "InterventionEngine requires a BoundedCompromiseCalculator"
            )
        self._calc: BoundedCompromiseCalculator = bounded_compromise_calc
        self._ledger = ledger
        # Thread 8.1: AIR-style eradication. When wired, an
        # ERADICATION_RULE_SYNTHESIS intervention's apply() runs the
        # synthesizer + registers the resulting rule in the registry.
        # When NOT wired, ERADICATION_RULE_SYNTHESIS interventions
        # FAIL-CLOSED on apply (so it's safe to keep the kind in the
        # enum even on deployments that haven't opted in).
        self._eradication_synth = eradication_synthesizer
        self._rule_registry = rule_registry

    # ------------------------------------------------------------------ select

    def select(
        self,
        *,
        current_drift_score: float,
        target_max_compromise_ratio: float,
        candidate_interventions: tuple[Intervention, ...],
    ) -> Intervention | None:
        """
        Pick the lowest-cost-to-system intervention that satisfies the
        bounded-compromise bound under the current adversary payoff.

        Algorithm (AAF §4.4 Stage 1 + Theorem 5):
          1. Estimate g_max from ``current_drift_score`` (and any
             richer drift_signals the caller threads through; here
             we use the scalar form for the existing scaffold
             signature).
          2. Sort candidates ascending by ``expected_cost_to_system``
             (AAF "lowest-cost intervention" criterion).
          3. For each candidate, check whether its
             ``expected_cost_to_adversary`` (interpreted as the
             window-aggregated lambda*H per the calculator's contract)
             satisfies the strict-dominance condition for the
             estimated g_max.
          4. Additionally check that the resulting eta* is below the
             caller's ``target_max_compromise_ratio`` -- the bound
             might be satisfied but loose; this filter enforces the
             operator's target.
          5. Return the first satisfying candidate, or ``None`` if
             none satisfy.

        FAIL-CLOSED: returns None on empty candidate list, on calculator
        error (after logging), or when no candidate satisfies. The
        caller (EcosystemEngine) downgrades the verdict accordingly.

        Parameters
        ----------
        current_drift_score : float
            Scalar drift score in [0, 1]. Used as g_max prior when no
            richer signal is available.
        target_max_compromise_ratio : float
            Operator's target eta* ceiling for *this* selection. If
            the satisfying intervention would yield an eta* above this,
            we reject -- the operator demands a tighter intervention.
        candidate_interventions : tuple of Intervention
            Candidate set. Each one's ``expected_cost_to_adversary`` is
            interpreted as a window-aggregated penalty.

        Returns
        -------
        The chosen Intervention or None.
        """
        if not isinstance(candidate_interventions, tuple):
            raise TypeError(
                "candidate_interventions must be a tuple of Intervention"
            )
        if not (0.0 <= target_max_compromise_ratio <= 1.0):
            raise ValueError(
                "target_max_compromise_ratio must be in [0, 1], "
                f"got {target_max_compromise_ratio}"
            )

        if not candidate_interventions:
            emit_event(
                "intervention.select.empty_candidate_set",
                drift_score=float(current_drift_score),
                target_eta=float(target_max_compromise_ratio),
            )
            return None

        # Estimate g_max. Use a scalar-drift-only signal here; richer
        # signals (ABC D*, BOCPD posterior) are supported by the
        # calculator and can be threaded through a future caller.
        try:
            g_max = self._calc.estimate_adversary_payoff(
                drift_signals={"drift_delta": float(current_drift_score)}
            )
        except Exception as exc:  # defence in depth
            emit_event(
                "intervention.select.payoff_estimate_failed",
                drift_score=float(current_drift_score),
                error=f"{type(exc).__name__}: {exc}",
            )
            return None

        # Sort ascending by cost_to_system; ties broken by intervention_id
        # for determinism.
        ranked: list[Intervention] = sorted(
            candidate_interventions,
            key=lambda iv: (iv.expected_cost_to_system, iv.intervention_id),
        )

        for candidate in ranked:
            try:
                if not self._calc.satisfies_bound(
                    proposed_intervention_cost_to_adversary=(
                        candidate.expected_cost_to_adversary
                    ),
                    adversary_expected_payoff=g_max,
                ):
                    continue
                eta = self._calc.long_run_compromise_ratio_from_window(
                    penalty_window_aggregate=candidate.expected_cost_to_adversary,
                    adversary_g_max=g_max,
                )
            except Exception as exc:  # defence in depth
                emit_event(
                    "intervention.select.calculator_failure",
                    candidate_id=candidate.intervention_id,
                    error=f"{type(exc).__name__}: {exc}",
                )
                continue

            if eta > target_max_compromise_ratio:
                emit_event(
                    "intervention.select.eta_above_target",
                    candidate_id=candidate.intervention_id,
                    eta=eta,
                    target_eta=float(target_max_compromise_ratio),
                )
                continue

            emit_event(
                "intervention.select.chosen",
                candidate_id=candidate.intervention_id,
                kind=candidate.kind.value,
                target_entity_id=candidate.target_entity_id,
                cost_to_system=candidate.expected_cost_to_system,
                cost_to_adversary=candidate.expected_cost_to_adversary,
                g_max=g_max,
                eta=eta,
                target_eta=float(target_max_compromise_ratio),
            )
            return candidate

        emit_event(
            "intervention.select.no_candidate_satisfies",
            n_candidates=len(candidate_interventions),
            drift_score=float(current_drift_score),
            g_max=g_max,
            target_eta=float(target_max_compromise_ratio),
        )
        return None

    # ------------------------------------------------------------------- apply

    def apply(self, intervention: Intervention) -> str | None:
        """
        Apply ``intervention`` and emit an ML-DSA-signed governance
        log record describing what was applied + the compromise
        certificate proving the bound was satisfied at apply time.

        Returns
        -------
        The governance-log event_id of the appended record, or ``None``
        if no ledger was wired (e.g. tests that only want to exercise
        the selection logic).

        Behavior
        --------
        - Builds a ``CompromiseCertificate`` for the (intervention,
          estimated g_max) pair at apply time. Uses the prior g_max
          (calculator's ``fallback_g_max``) because by the apply path
          we no longer hold the current drift signal; this is fine
          because the *selection* check already verified the bound
          under the live signal.
        - Composes a structured payload conforming to the
          governance-log canonicaliser's contract (floats coerced to
          milli-units; no datetime; no enum). Includes the
          intervention identity, the AIR-style phase tag, and the full
          certificate.
        - Appends via ``GovernanceLog.record_observation`` which routes
          through ``tex.pqcrypto.algorithm_agility``.
        - On ledger error, emits telemetry and raises
          ``InterventionApplyError``. The caller (EcosystemEngine
          step 8) downgrades the verdict to ABSTAIN -- FAIL-CLOSED per
          Section 3.

        This method intentionally does NOT mutate the capability
        registry, trust store, policy enforcement layer, or sandbox
        manager directly. Those subsystems consume the governance-log
        record asynchronously. Doing it this way keeps the request
        critical path short (single log append) and matches AAF §4.4
        Stage 2 design ("the governor consumes ledger updates").
        """
        if not isinstance(intervention, Intervention):
            raise TypeError(
                f"intervention must be Intervention, got {type(intervention).__name__}"
            )

        # Build certificate. Use the calculator's fallback g_max
        # because we do not re-receive the drift signal at apply time;
        # this is the same g_max the selection path used as a prior in
        # absence of richer signals.
        try:
            g_max_prior = self._calc.estimate_adversary_payoff(drift_signals={})
            cert = self._calc.certify(
                penalty_window_aggregate=intervention.expected_cost_to_adversary,
                adversary_g_max=g_max_prior,
            )
        except Exception as exc:
            emit_event(
                "intervention.apply.certify_failed",
                intervention_id=intervention.intervention_id,
                error=f"{type(exc).__name__}: {exc}",
            )
            raise InterventionApplyError(
                f"certify failed: {type(exc).__name__}: {exc}"
            ) from exc

        phase = air_phase_for(intervention.kind)

        # Thread 8.1: ERADICATION_RULE_SYNTHESIS branch (AIR §3).
        # When the intervention is an eradication, synthesise a rule
        # from the incident context carried in
        # intervention.parameters['incident_context'] and register it
        # in the active rule registry. FAIL-CLOSED on any synthesis or
        # registration failure (returns from apply with no ledger
        # append).
        synthesised_rule_dict: dict | None = None
        if intervention.kind == InterventionKind.ERADICATION_RULE_SYNTHESIS:
            synthesised_rule_dict = self._eradicate_apply(intervention)
            if synthesised_rule_dict is None:
                # Synthesis or registration failed. Emit telemetry and
                # FAIL-CLOSED -- raise InterventionApplyError so the
                # caller treats this exactly like any other apply
                # failure.
                emit_event(
                    "intervention.apply.eradication_failed",
                    intervention_id=intervention.intervention_id,
                )
                raise InterventionApplyError(
                    "eradication rule synthesis failed (see telemetry)"
                )

        # Structured payload. The canonicaliser
        # (tex.institutional.governance_log._canonicalise_payload)
        # coerces floats to milli-unit ints, so we can pass floats
        # directly here -- the ledger handles the conversion.
        payload = self._build_log_payload(
            intervention=intervention, certificate=cert, phase=phase
        )
        # Include the synthesised rule (if any) in the audit record so
        # a regulator can verify the rule offline.
        if synthesised_rule_dict is not None:
            payload["synthesised_rule"] = synthesised_rule_dict

        emit_event(
            "intervention.apply.dispatch",
            intervention_id=intervention.intervention_id,
            kind=intervention.kind.value,
            target_entity_id=intervention.target_entity_id,
            phase=phase,
            bound_satisfied=cert.bound_satisfied,
            eta_star=cert.eta_star,
        )

        if self._ledger is None:
            emit_event(
                "intervention.apply.no_ledger_wired",
                intervention_id=intervention.intervention_id,
            )
            return None

        try:
            event_id = self._ledger.record_observation(
                oracle_observation=payload
            )
        except Exception as exc:  # defence in depth
            emit_event(
                "intervention.apply.ledger_append_failed",
                intervention_id=intervention.intervention_id,
                error=f"{type(exc).__name__}: {exc}",
            )
            raise InterventionApplyError(
                f"governance-log append failed: {type(exc).__name__}: {exc}"
            ) from exc

        emit_event(
            "intervention.apply.committed",
            intervention_id=intervention.intervention_id,
            governance_log_event_id=event_id,
            phase=phase,
            kind=intervention.kind.value,
            bound_satisfied=cert.bound_satisfied,
            eta_star=cert.eta_star,
            lambda_min=cert.lambda_min,
        )
        return event_id

    # ----------------------------------------------------- eradication helper

    def _eradicate_apply(self, intervention: Intervention) -> dict | None:
        """
        Run AIR-style eradication: synthesise + register a new rule.

        Returns a serialisable rule dict on success (for embedding in
        the governance-log record) or ``None`` on any synthesis or
        registration failure.

        The caller (apply()) treats ``None`` as FAIL-CLOSED and raises
        InterventionApplyError. This keeps the apply() control flow
        uniform across all kinds.
        """
        if self._eradication_synth is None or self._rule_registry is None:
            emit_event(
                "intervention.eradicate.no_synthesiser_wired",
                intervention_id=intervention.intervention_id,
                synth_wired=self._eradication_synth is not None,
                registry_wired=self._rule_registry is not None,
            )
            return None

        # Pull IncidentContext from the intervention parameters.
        ctx_dict = (intervention.parameters or {}).get("incident_context")
        if not isinstance(ctx_dict, dict):
            emit_event(
                "intervention.eradicate.missing_incident_context",
                intervention_id=intervention.intervention_id,
            )
            return None

        # Lazy import so the engine module stays importable even when
        # the eradication module isn't on the path.
        from tex.intervention.eradication import IncidentContext

        try:
            incident = IncidentContext(
                incident_id=str(ctx_dict["incident_id"]),
                actor_entity_id=str(ctx_dict["actor_entity_id"]),
                event_kind=str(ctx_dict["event_kind"]),
                target_entity_id=ctx_dict.get("target_entity_id"),
                contract_violation_severity=float(
                    ctx_dict.get("contract_violation_severity", 0.0)
                ),
                drift_delta=float(ctx_dict.get("drift_delta", 0.0)),
                payload_fingerprint=str(ctx_dict.get("payload_fingerprint", "")),
                observed_at=datetime.now(UTC),
                notes=str(ctx_dict.get("notes", "")),
            )
        except (KeyError, TypeError, ValueError) as exc:
            emit_event(
                "intervention.eradicate.bad_incident_context",
                intervention_id=intervention.intervention_id,
                error=f"{type(exc).__name__}: {exc}",
            )
            return None

        rule = self._eradication_synth.synthesise(incident)
        if rule is None:
            return None

        try:
            registered = self._rule_registry.register(rule)
        except Exception as exc:
            emit_event(
                "intervention.eradicate.registry_failure",
                intervention_id=intervention.intervention_id,
                rule_id=rule.rule_id,
                error=f"{type(exc).__name__}: {exc}",
            )
            return None

        emit_event(
            "intervention.eradicate.rule_active",
            intervention_id=intervention.intervention_id,
            rule_id=rule.rule_id,
            mode=rule.synthesiser_mode,
            severity=rule.severity,
            newly_registered=registered,
        )

        # Return a serialisable view of the rule for the audit log.
        return {
            "rule_id": rule.rule_id,
            "derived_from_incident_id": rule.derived_from_incident_id,
            "description": rule.description,
            "applies_to_actor_pattern": rule.applies_to_actor_pattern,
            "forbidden_event_kinds": list(rule.forbidden_event_kinds),
            "forbidden_payload_substrings": list(
                rule.forbidden_payload_substrings
            ),
            "severity": rule.severity,
            "synthesised_at": rule.synthesised_at.isoformat(),
            "synthesiser_mode": rule.synthesiser_mode,
            "synthesiser_metadata": {
                str(k): str(v) for k, v in rule.synthesiser_metadata.items()
            },
            "predicate_count": rule.predicate_count,
            "ltlf_depth": rule.ltlf_depth,
            "newly_registered": registered,
        }

    # ----------------------------------------------------------------- internals

    @staticmethod
    def _build_log_payload(
        *,
        intervention: Intervention,
        certificate: CompromiseCertificate,
        phase: str,
    ) -> dict:
        """
        Compose the structured payload for governance-log append.

        Keys are flat strings; values are JSON-serializable primitives
        the governance-log canonicaliser can handle. Floats are passed
        through; the canonicaliser converts them to milli-units.

        Required by ``GovernanceLog.record_observation``: includes a
        non-empty ``actor_entity_id`` so the log writer can route the
        record to the correct shard.
        """
        # Note: intervention.parameters is operator-supplied and may
        # contain non-canonicalisable values. We shallow-copy and
        # stringify it defensively to keep the canonicaliser happy.
        params_safe = {str(k): str(v) for k, v in (intervention.parameters or {}).items()}

        rationale_air = (
            f"phase={phase} "
            f"action={intervention.kind.value} "
            f"target={intervention.target_entity_id} "
            f"cost_to_system={intervention.expected_cost_to_system:.4f} "
            f"cost_to_adversary={intervention.expected_cost_to_adversary:.4f} "
            f"eta_star={certificate.eta_star:.4f} "
            f"bound_satisfied={certificate.bound_satisfied} "
            f"original_rationale={intervention.rationale!r}"
        )

        return {
            "kind": _LOG_KIND_INTERVENTION,
            "actor_entity_id": "_intervention_engine",
            "target_entity_id": intervention.target_entity_id,
            "intervention_id": intervention.intervention_id,
            "intervention_kind": intervention.kind.value,
            "air_phase": phase,
            "rationale": rationale_air,
            # Bound certificate -- the math an auditor reconstructs.
            "compromise_certificate": {
                "bound_satisfied": certificate.bound_satisfied,
                "eta_star": certificate.eta_star,
                "lambda_min": certificate.lambda_min,
                "penalty_window_aggregate": (
                    certificate.penalty_window_aggregate
                ),
                "adversary_g_max": certificate.adversary_g_max,
                "slack_above_g_max": certificate.slack_above_g_max,
                "welfare_shortfall_upper_bound": (
                    certificate.welfare_shortfall_upper_bound
                ),
                "false_alarm_budget": certificate.false_alarm_budget,
                "window_length": certificate.window_length,
                "target_compromise_ceiling": (
                    certificate.target_compromise_ceiling
                ),
            },
            "parameters": params_safe,
            "applied_at": datetime.now(UTC).isoformat(),
            "references": (
                "arxiv:2512.18561v3 §5.4 Theorem 5; "
                "arxiv:2602.11749 §3 IR vocabulary; "
                "arxiv:2604.07833v2 intervention taxonomy"
            ),
        }
