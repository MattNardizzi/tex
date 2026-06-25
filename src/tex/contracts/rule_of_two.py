"""
Rule-of-Two structural contract.

[Architecture: Layer 4 (Execution Governance)] — feeds the structural FORBID
floor (``tex.specialists.structural_floor``).

The principle
------------
Meta's "Agents Rule of Two: A Practical Approach to AI Agent Security"
(Meta AI, 2025-10-31, https://ai.meta.com/blog/practical-ai-agent-security/),
which formalises Simon Willison's "lethal trifecta": within a single agent
session, an agent must satisfy **at most two** of these three properties, or it
is exposed to prompt-injection-to-exfiltration with no robust defense —

  (A) it processes **untrustworthy input** (UNTRUSTED integrity on the FIDES
      lattice — tool outputs, retrieved docs, third-party messages);
  (B) it has **access to sensitive systems or private data** (sensitive
      confidentiality, >= CONFIDENTIAL on the FIDES lattice);
  (C) it can **change state or communicate externally** (a state-changing,
      irreversible, or egress action).

When all three hold and the agent is operating **without reliable human
oversight**, the trifecta is structurally present and the action must not run
autonomously → **FORBID**.

Why this is a structural proof, not a probability
-------------------------------------------------
The trifecta is a deterministic conjunction over labels the flow already
carries (the FIDES dual-axis capability labels from the IFC home
``tex.governance.private_data_exec.ifc.capability_compat``)
plus the action's state-change character. It is not an estimate. That is what
makes it eligible for the structural FORBID floor, alongside PCAS/CaMeL/IFC
proofs — a deterministic structural mitigation a paraphrase cannot route
around. (Nasr et al., "The Attacker Moves Second", arXiv:2510.09023, 2025,
demonstrates that adaptive attacks bypass a dozen recent detector-based
defenses; we read that as motivation to prefer structural proofs over
probabilistic detectors — an inference from the paper, not its stated thesis.)

Relationship to the IFC engine's trifecta
------------------------------------------
``tex.governance.private_data_exec.ifc.engine`` already detects
``ifc.rule_of_two_trifecta`` over a full **provenance graph**. This contract is
the **lightweight, label-driven** sibling: it fires from CaMeL FIDES labels (or
three declared buckets) supplied on the request, for the common case where the
caller has capability context but has not built an IFC provenance graph. Both
converge on the same FORBID; neither is redundant because their *inputs* differ.

Doctrine: FORBID needs a proof; uncertainty resolves to ABSTAIN
---------------------------------------------------------------
This contract fires **only** when all three buckets are affirmatively present.
A bucket whose evidence is absent is treated as **not proven** (not as a
conservative "assume present") — because a structural FORBID must be a proof,
not a guess. A flow that is merely *suspicious* but unproven trifecta stays on
the ordinary pipeline (which may ABSTAIN); it does not get a fabricated
structural FORBID here. This is opt-in: with no ``rule_of_two`` metadata the
contract is a zero-cost no-op.

Opt-in input shape (``request.metadata["rule_of_two"]``)
--------------------------------------------------------
Either declare the buckets directly::

    {"untrusted_input": true, "sensitive_access": true, "state_change": true,
     "human_oversight": false}

or supply FIDES-labeled sources + an action descriptor and let the contract
derive them::

    {"capabilities": [
        {"level": "UNTRUSTED", "confidentiality": "PUBLIC", "source": "email"},
        {"level": "TRUSTED",   "confidentiality": "RESTRICTED", "source": "crm"}],
     "action": {"state_change": true, "external": true, "irreversible": false},
     "human_oversight": false}

Explicit booleans take precedence over derived ones. ``human_oversight: true``
means the trifecta is acknowledged and supervised — the agent is not autonomous
— so it does **not** FORBID (Meta's escape hatch). Default oversight is False.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping

from tex.governance.private_data_exec.ifc.capability_compat import (
    CapabilityLevel,
    ConfidentialityLevel,
)


_METADATA_KEY = "rule_of_two"
RULE_OF_TWO_CODE = "rule_of_two.trifecta"
RULE_OF_TWO_SPECIALIST = "rule_of_two"


@dataclass(frozen=True, slots=True)
class RuleOfTwoOutcome:
    """Result of evaluating the Rule-of-Two contract for one request."""

    fired: bool
    untrusted_input: bool
    sensitive_access: bool
    state_change: bool
    human_oversight: bool
    reason: str
    code: str
    evidence: dict[str, Any] = field(default_factory=dict)

    @property
    def present_buckets(self) -> tuple[str, ...]:
        names = []
        if self.untrusted_input:
            names.append("untrusted_input")
        if self.sensitive_access:
            names.append("sensitive_access")
        if self.state_change:
            names.append("state_change")
        return tuple(names)


NEUTRAL_RULE_OF_TWO = RuleOfTwoOutcome(
    fired=False,
    untrusted_input=False,
    sensitive_access=False,
    state_change=False,
    human_oversight=False,
    reason="",
    code=RULE_OF_TWO_CODE,
    evidence={},
)


def _as_bool(value: Any) -> bool:
    """Strict-ish truthiness: only real True / "true" / 1 count as present.

    Deliberately conservative — an unparseable or absent value is *not proven*,
    so it reads as False (the trifecta is not fabricated).
    """
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value == 1
    if isinstance(value, str):
        return value.strip().casefold() in ("true", "1", "yes")
    return False


def _derive_from_capabilities(raw: Mapping[str, Any]) -> tuple[bool, bool, dict]:
    """Derive (untrusted_input, sensitive_access) from FIDES-labeled sources.

    A source counts toward untrusted_input if its integrity level resolves to
    UNTRUSTED; toward sensitive_access if its confidentiality is_sensitive
    (>= CONFIDENTIAL). Unknown level/confidentiality strings are ignored
    (not proven), never defaulted to the dangerous tier.
    """
    caps = raw.get("capabilities")
    if not isinstance(caps, (list, tuple)):
        return False, False, {}

    untrusted_sources: list[str] = []
    sensitive_sources: list[str] = []
    for entry in caps:
        if not isinstance(entry, Mapping):
            continue
        source = str(entry.get("source", "?"))
        level_name = str(entry.get("level", "")).strip().upper()
        conf_name = str(entry.get("confidentiality", "")).strip().upper()
        if level_name in CapabilityLevel.__members__:
            if CapabilityLevel[level_name] is CapabilityLevel.UNTRUSTED:
                untrusted_sources.append(source)
        if conf_name in ConfidentialityLevel.__members__:
            if ConfidentialityLevel[conf_name].is_sensitive:
                sensitive_sources.append(source)

    evidence: dict[str, Any] = {}
    if untrusted_sources:
        evidence["untrusted_sources"] = untrusted_sources
    if sensitive_sources:
        evidence["sensitive_sources"] = sensitive_sources
    return bool(untrusted_sources), bool(sensitive_sources), evidence


def _derive_state_change(raw: Mapping[str, Any]) -> tuple[bool, dict]:
    """Derive the state-change bucket from an ``action`` descriptor."""
    action = raw.get("action")
    if not isinstance(action, Mapping):
        return False, {}
    triggers = {
        k: _as_bool(action.get(k))
        for k in ("state_change", "external", "irreversible", "egress")
    }
    fired = any(triggers.values())
    evidence = {f"action_{k}": v for k, v in triggers.items() if v}
    return fired, evidence


def classify_rule_of_two(raw: Mapping[str, Any]) -> RuleOfTwoOutcome:
    """Pure classifier over a ``rule_of_two`` metadata block."""
    evidence: dict[str, Any] = {}

    # Bucket A/B: explicit booleans win; otherwise derive from FIDES labels.
    if "untrusted_input" in raw or "sensitive_access" in raw:
        untrusted = _as_bool(raw.get("untrusted_input"))
        sensitive = _as_bool(raw.get("sensitive_access"))
    else:
        untrusted, sensitive, derived_ev = _derive_from_capabilities(raw)
        evidence.update(derived_ev)

    # Bucket C: explicit boolean wins; otherwise derive from the action.
    if "state_change" in raw:
        state_change = _as_bool(raw.get("state_change"))
    else:
        state_change, sc_ev = _derive_state_change(raw)
        evidence.update(sc_ev)

    human_oversight = _as_bool(raw.get("human_oversight"))

    trifecta = untrusted and sensitive and state_change
    fired = trifecta and not human_oversight

    if fired:
        reason = (
            "Rule-of-Two trifecta proven: this flow simultaneously (A) ingests "
            "untrusted input, (B) accesses sensitive data, and (C) changes state "
            "or communicates externally, with no reliable human oversight. Per "
            "Meta's Agents Rule of Two, an autonomous agent must hold at most two "
            "of these three — all three is the lethal-trifecta exfiltration "
            "surface. Structural FORBID."
        )
    elif trifecta and human_oversight:
        reason = (
            "Rule-of-Two trifecta present but declared under reliable human "
            "oversight — not autonomous, so not forbidden by this contract."
        )
    else:
        reason = ""

    return RuleOfTwoOutcome(
        fired=fired,
        untrusted_input=untrusted,
        sensitive_access=sensitive,
        state_change=state_change,
        human_oversight=human_oversight,
        reason=reason,
        code=RULE_OF_TWO_CODE,
        evidence=evidence,
    )


def evaluate_rule_of_two(request: Any) -> RuleOfTwoOutcome:
    """Evaluate the Rule-of-Two contract against a PDP request.

    Returns ``NEUTRAL_RULE_OF_TWO`` (a zero-cost no-op) when the request carries
    no ``rule_of_two`` metadata block.
    """
    metadata = getattr(request, "metadata", None)
    if not isinstance(metadata, Mapping):
        return NEUTRAL_RULE_OF_TWO
    raw = metadata.get(_METADATA_KEY)
    if not isinstance(raw, Mapping):
        return NEUTRAL_RULE_OF_TWO
    return classify_rule_of_two(raw)


__all__ = [
    "RuleOfTwoOutcome",
    "NEUTRAL_RULE_OF_TWO",
    "RULE_OF_TWO_CODE",
    "RULE_OF_TWO_SPECIALIST",
    "classify_rule_of_two",
    "evaluate_rule_of_two",
]
