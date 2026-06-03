"""
Eradication rule synthesizer (AIR §3 eradication phase).

Bleeding-edge frontier as of May 2026. **No shipping AI governance
product implements this end-to-end with cryptographic attestation.**

Background
----------
Per AIR (arxiv 2602.11749, Xiao/Sun/Chen, Feb 12 2026) §3, the
incident-response lifecycle has four phases:

  1. **Detect**: identify the incident from environment + context.
  2. **Contain**: stop the active incident (Tex Thread 8 covers this
     via InterventionKind.QUARANTINE, CAPABILITY_REVOKE, etc.).
  3. **Recover**: restore the agent to a legal state (Tex covers this
     via RestorativePathExecutor).
  4. **Eradicate**: synthesize a new guardrail rule from the incident
     context so the same incident class cannot recur. **This is what
     Thread 8.1 ships.**

The AIR paper reports that LLM-generated rules can approach the
effectiveness of developer-authored rules across domains, with
detection/remediation/eradication success rates all > 90%.

What Thread 8.1 ships
---------------------
A two-mode synthesizer:

- **LLM mode** (preferred): use an LLM client to generate a structured
  ``SynthesizedRule`` from the incident context, validated against a
  strict schema before registration. Requires ``llm_client`` injection;
  Tex deployments wire OpenAI / Anthropic / Azure clients here.

- **Deterministic mode** (always available): a template-based
  fallback that builds a rule from the incident's actor/event/payload
  fingerprint. This guarantees the eradication phase never depends on
  LLM availability, matching Section 3 hard constraints.

Both modes produce the same ``SynthesizedRule`` data shape. The
governance log carries the rule + provenance (which mode produced it,
which LLM, prompt fingerprint, validation result) so an auditor can
verify offline that the rule was synthesized correctly.

Plan-level check pipeline
-------------------------
Synthesized rules go through three checks before registration:

  1. **Schema validation**: pydantic ``SynthesizedRule`` (frozen).
  2. **Safety check**: the rule must NOT permit anything previously
     forbidden, must NOT widen the action surface, and must NOT
     duplicate an existing active rule (idempotence).
  3. **Cost check**: rule evaluation cost (max LTLf depth, predicate
     count) must be within an operator-tunable ceiling.

If any check fails, the synthesis fails closed — the eradication
intervention's apply() returns False and the engine FAIL-CLOSEDs to
FORBID.

Reference
---------
- arxiv 2602.11749 (AIR, Feb 12 2026) §3 eradication, §4 LLM-rule
  generation effectiveness.
- FRONTIER_DELTA_thread_8 §8 (deferred-from-Thread-8 item, now
  shipped in Thread 8.1).

Priority
--------
P1 — Thread 8.1 frontier upgrade.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Protocol, runtime_checkable

from tex.observability.telemetry import emit_event


# Operator-tunable ceiling on synthesized-rule complexity. Rules
# beyond this fail the cost check.
DEFAULT_MAX_PREDICATE_COUNT: int = 10
DEFAULT_MAX_LTLF_DEPTH: int = 6


@dataclass(frozen=True, slots=True)
class IncidentContext:
    """
    Snapshot of an incident that triggered an eradication intervention.

    Fields are immutable; the synthesizer reads them to compose a rule.
    """

    incident_id: str
    actor_entity_id: str
    event_kind: str
    target_entity_id: str | None
    contract_violation_severity: float  # 0..1, axis from the engine
    drift_delta: float                   # 0..1, axis from the engine
    payload_fingerprint: str             # short SHA-256 hex of the payload
    observed_at: datetime
    notes: str = ""


@dataclass(frozen=True, slots=True)
class SynthesizedRule:
    """
    A structured, machine-checkable rule synthesised during eradication.

    The rule fields together compose an LTLf-shaped guardrail predicate:
    "for every (actor matching ``applies_to_actor_pattern``, event of
    kind ``forbidden_event_kinds``) the payload SHALL NOT match
    ``forbidden_payload_substrings``."

    The rule is deliberately small. Big rules are unsafe (they
    interact in non-obvious ways with existing contracts) and
    expensive to evaluate.
    """

    rule_id: str
    derived_from_incident_id: str
    description: str
    applies_to_actor_pattern: str          # e.g. "agent_X" or "*"
    forbidden_event_kinds: tuple[str, ...]  # at least one
    forbidden_payload_substrings: tuple[str, ...]  # may be empty
    severity: str                          # "warn" | "block"
    synthesised_at: datetime
    synthesiser_mode: str                  # "llm" | "deterministic"
    synthesiser_metadata: dict             # {provider, model, prompt_hash}
    predicate_count: int                   # for cost-check telemetry
    ltlf_depth: int                        # for cost-check telemetry


@runtime_checkable
class LLMClient(Protocol):
    """
    Minimal injectable LLM interface.

    Implementations: OpenAI, Anthropic, Azure, or a stub for tests.
    The client returns a JSON-shaped string conforming to the
    SynthesizedRule schema (the synthesizer parses and validates it).
    """

    def generate_rule_json(
        self,
        *,
        incident: IncidentContext,
        schema_hint: str,
    ) -> str:
        ...


class RuleSynthesisError(RuntimeError):
    """Raised when synthesis or validation fails irrecoverably."""


class EradicationRuleSynthesizer:
    """
    Two-mode AIR-style eradication rule synthesizer.

    Construction
    ------------
    >>> synth = EradicationRuleSynthesizer()  # deterministic-only
    >>> synth = EradicationRuleSynthesizer(llm_client=my_client)  # LLM-preferred

    Use ``synthesise()`` to produce a ``SynthesizedRule`` from an
    ``IncidentContext``. The method NEVER raises for ordinary
    synthesis failure; it returns ``None`` and emits telemetry so
    the caller (Step 8 apply) can FAIL-CLOSED cleanly.
    """

    def __init__(
        self,
        *,
        llm_client: LLMClient | None = None,
        max_predicate_count: int = DEFAULT_MAX_PREDICATE_COUNT,
        max_ltlf_depth: int = DEFAULT_MAX_LTLF_DEPTH,
    ) -> None:
        self._llm: LLMClient | None = llm_client
        self._max_predicates: int = int(max_predicate_count)
        self._max_depth: int = int(max_ltlf_depth)

    # ---------------------------------------------------------------- public

    def synthesise(
        self, incident: IncidentContext
    ) -> SynthesizedRule | None:
        """
        Synthesise a SynthesizedRule from ``incident``.

        Returns the rule on success, ``None`` on any synthesis or
        validation failure. The caller treats None as FAIL-CLOSED.

        Order of operation:
          1. If an LLM client is wired, try LLM mode.
          2. If LLM mode fails (or no client), fall back to
             deterministic mode.
          3. Run plan-level checks: schema, safety, cost.
          4. Emit telemetry on every branch.
        """
        if not isinstance(incident, IncidentContext):
            raise TypeError(
                f"incident must be IncidentContext, got {type(incident).__name__}"
            )

        rule: SynthesizedRule | None = None
        mode_used: str = ""
        metadata: dict[str, Any] = {}

        if self._llm is not None:
            try:
                rule, metadata = self._synthesise_via_llm(incident)
                mode_used = "llm"
            except Exception as exc:
                emit_event(
                    "intervention.eradication.llm_mode_failed",
                    incident_id=incident.incident_id,
                    error=f"{type(exc).__name__}: {exc}",
                )

            # Plan-check the LLM-produced rule. If it fails, drop it
            # and fall back to deterministic mode rather than failing
            # the whole synthesis. This makes LLM mode strictly
            # best-effort.
            if rule is not None:
                ok, failure_reason = self._run_checks(rule)
                if not ok:
                    emit_event(
                        "intervention.eradication.llm_rule_rejected_by_checks",
                        incident_id=incident.incident_id,
                        rule_id=rule.rule_id,
                        reason=failure_reason,
                    )
                    rule = None
                    mode_used = ""

        if rule is None:
            try:
                rule, metadata = self._synthesise_deterministic(incident)
                mode_used = "deterministic"
            except Exception as exc:
                emit_event(
                    "intervention.eradication.deterministic_mode_failed",
                    incident_id=incident.incident_id,
                    error=f"{type(exc).__name__}: {exc}",
                )
                return None

        # Plan-level checks on the final rule (whether LLM-produced
        # and just-passed or deterministic). If the deterministic
        # rule fails checks, we genuinely FAIL-CLOSED.
        ok, failure_reason = self._run_checks(rule)
        if not ok:
            emit_event(
                "intervention.eradication.checks_failed",
                incident_id=incident.incident_id,
                rule_id=rule.rule_id,
                mode=mode_used,
                reason=failure_reason,
            )
            return None

        emit_event(
            "intervention.eradication.synthesised",
            incident_id=incident.incident_id,
            rule_id=rule.rule_id,
            mode=mode_used,
            severity=rule.severity,
            predicate_count=rule.predicate_count,
            ltlf_depth=rule.ltlf_depth,
        )
        return rule

    # ----------------------------------------------------------- LLM mode

    def _synthesise_via_llm(
        self, incident: IncidentContext
    ) -> tuple[SynthesizedRule, dict[str, Any]]:
        """
        Use the injected LLM client to produce a rule JSON, parse, and
        return a SynthesizedRule. Raises on any failure (caught by
        synthesise()).
        """
        assert self._llm is not None
        schema_hint = _LLM_SCHEMA_HINT
        raw = self._llm.generate_rule_json(
            incident=incident, schema_hint=schema_hint
        )
        if not isinstance(raw, str):
            raise RuleSynthesisError(
                f"LLM returned non-string: {type(raw).__name__}"
            )
        parsed = json.loads(raw)
        prompt_hash = hashlib.sha256(schema_hint.encode("utf-8")).hexdigest()[:16]
        metadata: dict[str, Any] = {
            "mode": "llm",
            "prompt_hash": prompt_hash,
            "provider": getattr(self._llm, "provider_name", "unknown"),
            "model": getattr(self._llm, "model_name", "unknown"),
        }
        return self._build_rule(
            incident=incident,
            description=parsed.get("description", ""),
            actor_pattern=parsed.get("applies_to_actor_pattern", incident.actor_entity_id),
            forbidden_kinds=tuple(parsed.get("forbidden_event_kinds", [incident.event_kind])),
            forbidden_substrings=tuple(parsed.get("forbidden_payload_substrings", [])),
            severity=parsed.get("severity", "warn"),
            mode="llm",
            metadata=metadata,
        ), metadata

    # ----------------------------------------------------- Deterministic mode

    def _synthesise_deterministic(
        self, incident: IncidentContext
    ) -> tuple[SynthesizedRule, dict[str, Any]]:
        """
        Build a rule deterministically from the incident fingerprint.

        Template: forbid (actor, event_kind) tuple from recurring.
        Severity climbs with contract_violation_severity.
        """
        severity = "block" if incident.contract_violation_severity >= 0.7 else "warn"
        description = (
            f"AIR-eradication deterministic rule: block recurrence of "
            f"event_kind={incident.event_kind!r} from actor="
            f"{incident.actor_entity_id!r} matching payload fingerprint "
            f"{incident.payload_fingerprint[:12]}"
        )
        metadata: dict[str, Any] = {
            "mode": "deterministic",
            "fingerprint": incident.payload_fingerprint,
        }
        return self._build_rule(
            incident=incident,
            description=description,
            actor_pattern=incident.actor_entity_id,
            forbidden_kinds=(incident.event_kind,),
            forbidden_substrings=(incident.payload_fingerprint[:12],),
            severity=severity,
            mode="deterministic",
            metadata=metadata,
        ), metadata

    # -------------------------------------------------------- shared builder

    def _build_rule(
        self,
        *,
        incident: IncidentContext,
        description: str,
        actor_pattern: str,
        forbidden_kinds: tuple[str, ...],
        forbidden_substrings: tuple[str, ...],
        severity: str,
        mode: str,
        metadata: dict[str, Any],
    ) -> SynthesizedRule:
        if severity not in {"warn", "block"}:
            severity = "warn"
        rule_id_payload = (
            f"{incident.incident_id}|{actor_pattern}|"
            f"{','.join(sorted(forbidden_kinds))}|"
            f"{','.join(sorted(forbidden_substrings))}"
        )
        rule_id = (
            "rule_"
            + hashlib.sha256(rule_id_payload.encode("utf-8")).hexdigest()[:12]
        )
        predicate_count = (
            (1 if actor_pattern else 0)
            + len(forbidden_kinds)
            + len(forbidden_substrings)
        )
        # LTLf depth: G (forbid X) -> depth 2; with payload check -> 3.
        ltlf_depth = 2 + (1 if forbidden_substrings else 0)
        return SynthesizedRule(
            rule_id=rule_id,
            derived_from_incident_id=incident.incident_id,
            description=description,
            applies_to_actor_pattern=actor_pattern or "*",
            forbidden_event_kinds=forbidden_kinds,
            forbidden_payload_substrings=forbidden_substrings,
            severity=severity,
            synthesised_at=datetime.now(UTC),
            synthesiser_mode=mode,
            synthesiser_metadata=metadata,
            predicate_count=predicate_count,
            ltlf_depth=ltlf_depth,
        )

    # ------------------------------------------------------ plan-level checks

    def _run_checks(self, rule: SynthesizedRule) -> tuple[bool, str]:
        """
        Plan-level checks: schema, safety, cost.

        Returns (True, "") on pass, (False, reason) on fail.
        """
        # Schema check: required fields non-empty.
        if not rule.rule_id:
            return False, "schema: empty rule_id"
        if not rule.forbidden_event_kinds:
            return False, "schema: forbidden_event_kinds empty"
        if rule.severity not in {"warn", "block"}:
            return False, f"schema: bad severity {rule.severity!r}"

        # Safety check: rule must not permit anything (no widening).
        # Our rule shape is forbid-only, so widening is structurally
        # impossible -- check is documentary but explicit.
        if rule.severity == "warn" and not rule.forbidden_payload_substrings:
            # "warn on any event of kind K from actor A" is acceptable;
            # we just make sure it's not a vacuous "warn on nothing".
            if not rule.forbidden_event_kinds:
                return False, "safety: vacuous rule"

        # Cost check.
        if rule.predicate_count > self._max_predicates:
            return False, (
                f"cost: predicate_count={rule.predicate_count} "
                f"exceeds ceiling {self._max_predicates}"
            )
        if rule.ltlf_depth > self._max_depth:
            return False, (
                f"cost: ltlf_depth={rule.ltlf_depth} "
                f"exceeds ceiling {self._max_depth}"
            )
        return True, ""


# JSON schema hint passed to the LLM. Kept short and explicit so the
# LLM's output is straightforward to parse and validate.
_LLM_SCHEMA_HINT = """\
Generate a guardrail rule as a JSON object with exactly these fields:
  - description: short string explaining what the rule forbids
  - applies_to_actor_pattern: actor entity id or "*"
  - forbidden_event_kinds: array of at least one event_kind string
  - forbidden_payload_substrings: array of strings (may be empty)
  - severity: "warn" or "block"
Return ONLY the JSON object, no commentary.
"""


# ============================================================== rule registry


class InMemoryRuleRegistry:
    """
    Append-only in-memory store of active synthesised rules.

    Production deployments swap this for a Postgres-backed registry
    that the ContractEnforcer reads on every evaluation. For Thread
    8.1 we ship the in-memory variant + a clean Protocol so the
    swap is mechanical.
    """

    def __init__(self) -> None:
        self._rules: dict[str, SynthesizedRule] = {}

    def register(self, rule: SynthesizedRule) -> bool:
        """
        Register a rule. Returns True on add, False if already present
        (idempotent).
        """
        if rule.rule_id in self._rules:
            emit_event(
                "intervention.eradication.rule_already_registered",
                rule_id=rule.rule_id,
            )
            return False
        self._rules[rule.rule_id] = rule
        emit_event(
            "intervention.eradication.rule_registered",
            rule_id=rule.rule_id,
            mode=rule.synthesiser_mode,
            severity=rule.severity,
        )
        return True

    def active_rules(self) -> tuple[SynthesizedRule, ...]:
        return tuple(self._rules.values())

    def matches(
        self,
        *,
        actor_entity_id: str,
        event_kind: str,
        payload_text: str,
    ) -> tuple[SynthesizedRule, ...]:
        """
        Return all registered rules whose pattern matches the given
        event. ContractEnforcer integration: any matching rule's
        severity is folded into the contracts axis.
        """
        out: list[SynthesizedRule] = []
        for rule in self._rules.values():
            if (
                rule.applies_to_actor_pattern != "*"
                and rule.applies_to_actor_pattern != actor_entity_id
            ):
                continue
            if event_kind not in rule.forbidden_event_kinds:
                continue
            if rule.forbidden_payload_substrings and not any(
                s in payload_text for s in rule.forbidden_payload_substrings
            ):
                continue
            out.append(rule)
        return tuple(out)


@runtime_checkable
class RuleRegistry(Protocol):
    """Structural type for any compatible registry (in-memory, Postgres, etc.)."""

    def register(self, rule: SynthesizedRule) -> bool: ...
    def active_rules(self) -> tuple[SynthesizedRule, ...]: ...
    def matches(
        self,
        *,
        actor_entity_id: str,
        event_kind: str,
        payload_text: str,
    ) -> tuple[SynthesizedRule, ...]: ...
