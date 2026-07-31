"""
STPA manifest YAML loader + coverage matrix builder.

Reference: Doshi et al. "Towards Verifiably Safe Tool Use for LLM
Agents." ICSE-NIER 2026 (arXiv:2601.08012).

Loads a YAML document containing the STPA artifacts (Stakeholder,
Loss, Hazard, SafetyConstraint, UCA, LossScenario, Requirement,
Specification, MCPLabel) and produces:

  1. A validated StpaManifest pydantic model.
  2. A coverage matrix mapping each UCA to the tuple of Tex defense
     modules that mitigate it (read transitively from LossScenarios
     that reference the UCA, and from Specifications that address
     hazards related to the UCA).
  3. A list of any UCAs with zero mitigations (the "uncovered" set —
     this is the audit-relevant gap that compliance officers want
     surfaced).

Manifest format
---------------
Top-level keys: stakeholders, losses, hazards, safety_constraints,
unsafe_control_actions, loss_scenarios, requirements, specifications,
mcp_labels. Each maps to a list of dicts whose keys correspond to the
fields of the respective dataclass in hazard_model.

Cross-references are validated:
  - Hazard.leads_to_losses must reference existing losses
  - SafetyConstraint.inverts_hazards must reference existing hazards
  - UCA.related_hazards must reference existing hazards
  - LossScenario.related_uca must reference an existing UCA
  - Requirement.addresses_hazards must reference existing hazards
  - Specification.refines_requirement must reference an existing requirement

Validation failures raise StpaManifestValidationError listing every
missing reference, so the operator gets the whole picture at once
rather than fixing one error and re-running.

Priority: P1.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping, Sequence

from pydantic import BaseModel, ConfigDict, Field

from tex.governance.stpa_specs.hazard_model import (
    EnforcementTier,
    Hazard,
    Loss,
    LossScenario,
    MCPLabel,
    Requirement,
    SafetyConstraint,
    Specification,
    Stakeholder,
    UnsafeControlAction,
)
from tex.observability import telemetry


class StpaManifestValidationError(ValueError):
    """Raised when manifest validation fails."""


class StpaManifest(BaseModel):
    """
    Full STPA manifest after validation.

    Built via ``load_manifest``. Stored as a pydantic v2 frozen model so
    it can be safely shared between threads / passed to the coverage
    builder without copy-on-write concerns.
    """

    model_config = ConfigDict(frozen=True, extra="forbid", arbitrary_types_allowed=True)

    stakeholders: tuple[Stakeholder, ...] = Field(default_factory=tuple)
    losses: tuple[Loss, ...] = Field(default_factory=tuple)
    hazards: tuple[Hazard, ...] = Field(default_factory=tuple)
    safety_constraints: tuple[SafetyConstraint, ...] = Field(default_factory=tuple)
    unsafe_control_actions: tuple[UnsafeControlAction, ...] = Field(default_factory=tuple)
    loss_scenarios: tuple[LossScenario, ...] = Field(default_factory=tuple)
    requirements: tuple[Requirement, ...] = Field(default_factory=tuple)
    specifications: tuple[Specification, ...] = Field(default_factory=tuple)
    mcp_labels: tuple[MCPLabel, ...] = Field(default_factory=tuple)


# ---------------------------------------------------------------------------
# Loader
# ---------------------------------------------------------------------------


def load_manifest(source: str | bytes | Path) -> StpaManifest:
    """
    Load and validate an STPA manifest from YAML.

    ``source`` may be:
      - a Path (file is read)
      - bytes (parsed directly)
      - a str — interpreted as a path if it points to an existing file,
        otherwise as inline YAML

    PyYAML is imported lazily; missing pyyaml raises a clear actionable
    error. This matches the pattern in
    tex.institutional.governance_graph.

    The manifest is fully cross-validated; every reference must resolve
    or the loader raises StpaManifestValidationError listing all
    failures together.
    """
    raw: object = _read_yaml(source)
    if not isinstance(raw, Mapping):
        raise StpaManifestValidationError(
            "manifest root must be a mapping with top-level keys"
        )

    stakeholders = tuple(_load_list(raw, "stakeholders", _build_stakeholder))
    losses = tuple(_load_list(raw, "losses", _build_loss))
    hazards = tuple(_load_list(raw, "hazards", _build_hazard))
    safety_constraints = tuple(
        _load_list(raw, "safety_constraints", _build_safety_constraint)
    )
    ucas = tuple(_load_list(raw, "unsafe_control_actions", _build_uca))
    loss_scenarios = tuple(_load_list(raw, "loss_scenarios", _build_loss_scenario))
    requirements = tuple(_load_list(raw, "requirements", _build_requirement))
    specifications = tuple(_load_list(raw, "specifications", _build_specification))
    mcp_labels = tuple(_load_list(raw, "mcp_labels", _build_mcp_label))

    # Cross-reference validation.
    errors: list[str] = []
    loss_ids = {l.loss_id for l in losses}
    hazard_ids = {h.hazard_id for h in hazards}
    uca_ids = {u.uca_id for u in ucas}
    requirement_ids = {r.requirement_id for r in requirements}

    for h in hazards:
        for ref in h.leads_to_losses:
            if ref not in loss_ids:
                errors.append(
                    f"hazard {h.hazard_id!r} references unknown loss {ref!r}"
                )
    for sc in safety_constraints:
        for ref in sc.inverts_hazards:
            if ref not in hazard_ids:
                errors.append(
                    f"safety_constraint {sc.constraint_id!r} references unknown hazard {ref!r}"
                )
    for u in ucas:
        for ref in u.related_hazards:
            if ref not in hazard_ids:
                errors.append(
                    f"uca {u.uca_id!r} references unknown hazard {ref!r}"
                )
    for ls in loss_scenarios:
        if ls.related_uca not in uca_ids:
            errors.append(
                f"loss_scenario {ls.scenario_id!r} references unknown uca {ls.related_uca!r}"
            )
    for r in requirements:
        for ref in r.addresses_hazards:
            if ref not in hazard_ids:
                errors.append(
                    f"requirement {r.requirement_id!r} references unknown hazard {ref!r}"
                )
    for s in specifications:
        if s.refines_requirement not in requirement_ids:
            errors.append(
                f"specification {s.spec_id!r} references unknown requirement "
                f"{s.refines_requirement!r}"
            )

    # Duplicate-id checks.
    for label, ids in (
        ("loss", [l.loss_id for l in losses]),
        ("hazard", [h.hazard_id for h in hazards]),
        ("uca", [u.uca_id for u in ucas]),
        ("loss_scenario", [ls.scenario_id for ls in loss_scenarios]),
        ("requirement", [r.requirement_id for r in requirements]),
        ("specification", [s.spec_id for s in specifications]),
        ("safety_constraint", [s.constraint_id for s in safety_constraints]),
        ("stakeholder", [s.stakeholder_id for s in stakeholders]),
    ):
        seen: set[str] = set()
        for i in ids:
            if i in seen:
                errors.append(f"duplicate {label} id: {i!r}")
            seen.add(i)

    if errors:
        raise StpaManifestValidationError(
            f"manifest validation failed with {len(errors)} error(s):\n  - "
            + "\n  - ".join(errors)
        )

    manifest = StpaManifest(
        stakeholders=stakeholders,
        losses=losses,
        hazards=hazards,
        safety_constraints=safety_constraints,
        unsafe_control_actions=ucas,
        loss_scenarios=loss_scenarios,
        requirements=requirements,
        specifications=specifications,
        mcp_labels=mcp_labels,
    )
    telemetry.emit_event(
        "stpa.manifest.loaded",
        n_losses=len(losses),
        n_hazards=len(hazards),
        n_ucas=len(ucas),
        n_loss_scenarios=len(loss_scenarios),
        n_specifications=len(specifications),
    )
    return manifest


def _read_yaml(source: str | bytes | Path) -> object:
    """
    Read YAML from a Path / bytes / str source.

    PyYAML is imported lazily; it is transitively present via
    ``uvicorn[standard]`` in requirements.txt but not declared as an
    explicit dependency. If the import fails the caller gets an
    actionable error.
    """
    try:
        import yaml  # type: ignore[import-not-found]
    except ImportError as exc:
        raise StpaManifestValidationError(
            "PyYAML is required to load STPA manifests. "
            "Install via: pip install pyyaml"
        ) from exc

    if isinstance(source, Path):
        return yaml.safe_load(source.read_bytes())
    if isinstance(source, bytes):
        return yaml.safe_load(source)
    if isinstance(source, str):
        candidate = Path(source)
        if (
            "\n" not in source
            and len(source) < 4096
            and candidate.exists()
            and candidate.is_file()
        ):
            return yaml.safe_load(candidate.read_bytes())
        return yaml.safe_load(source)
    raise StpaManifestValidationError(
        f"unsupported source type: {type(source).__name__}"
    )


# ---------------------------------------------------------------------------
# Per-artifact builders
# ---------------------------------------------------------------------------


def _load_list(
    raw: Mapping[str, Any],
    key: str,
    builder,  # type: ignore[no-untyped-def]
) -> list:
    items = raw.get(key, ()) or ()
    if not isinstance(items, Sequence) or isinstance(items, (str, bytes)):
        raise StpaManifestValidationError(
            f"manifest key {key!r} must be a list, got {type(items).__name__}"
        )
    return [builder(i) for i in items]


def _require(d: Mapping[str, Any], key: str, where: str) -> Any:
    if key not in d:
        raise StpaManifestValidationError(f"{where}: missing required field {key!r}")
    return d[key]


def _tuple_of_str(value: Any, where: str) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str):
        return (value,)
    if isinstance(value, Sequence):
        out: list[str] = []
        for v in value:
            if not isinstance(v, str):
                raise StpaManifestValidationError(
                    f"{where}: list element must be string, got {type(v).__name__}"
                )
            out.append(v)
        return tuple(out)
    raise StpaManifestValidationError(
        f"{where}: expected list of strings, got {type(value).__name__}"
    )


def _build_stakeholder(d: Mapping[str, Any]) -> Stakeholder:
    where = "stakeholder"
    return Stakeholder(
        stakeholder_id=str(_require(d, "stakeholder_id", where)),
        name=str(_require(d, "name", where)),
        is_direct=bool(d.get("is_direct", True)),
        values=_tuple_of_str(d.get("values", ()), where),
    )


def _build_loss(d: Mapping[str, Any]) -> Loss:
    where = "loss"
    return Loss(
        loss_id=str(_require(d, "loss_id", where)),
        description=str(_require(d, "description", where)),
    )


def _build_hazard(d: Mapping[str, Any]) -> Hazard:
    where = "hazard"
    return Hazard(
        hazard_id=str(_require(d, "hazard_id", where)),
        description=str(_require(d, "description", where)),
        leads_to_losses=_tuple_of_str(d.get("leads_to_losses", ()), where),
    )


def _build_safety_constraint(d: Mapping[str, Any]) -> SafetyConstraint:
    where = "safety_constraint"
    return SafetyConstraint(
        constraint_id=str(_require(d, "constraint_id", where)),
        description=str(_require(d, "description", where)),
        inverts_hazards=_tuple_of_str(d.get("inverts_hazards", ()), where),
    )


def _build_uca(d: Mapping[str, Any]) -> UnsafeControlAction:
    where = "uca"
    return UnsafeControlAction(
        uca_id=str(_require(d, "uca_id", where)),
        control_action=str(_require(d, "control_action", where)),
        context=str(_require(d, "context", where)),
        why_unsafe=str(_require(d, "why_unsafe", where)),
        related_hazards=_tuple_of_str(d.get("related_hazards", ()), where),
        guide_word=str(d.get("guide_word", "provided")),  # type: ignore[arg-type]
    )


def _build_loss_scenario(d: Mapping[str, Any]) -> LossScenario:
    where = "loss_scenario"
    return LossScenario(
        scenario_id=str(_require(d, "scenario_id", where)),
        causal_chain=_tuple_of_str(d.get("causal_chain", ()), where),
        related_uca=str(_require(d, "related_uca", where)),
        mitigation_modules=_tuple_of_str(d.get("mitigation_modules", ()), where),
    )


def _build_requirement(d: Mapping[str, Any]) -> Requirement:
    where = "requirement"
    return Requirement(
        requirement_id=str(_require(d, "requirement_id", where)),
        description=str(_require(d, "description", where)),
        addresses_hazards=_tuple_of_str(d.get("addresses_hazards", ()), where),
    )


def _build_specification(d: Mapping[str, Any]) -> Specification:
    where = "specification"
    tier_value = str(_require(d, "enforcement_tier", where))
    valid_tiers = {"blocklist", "mustlist", "allowlist", "confirmation"}
    if tier_value not in valid_tiers:
        raise StpaManifestValidationError(
            f"{where}: enforcement_tier must be one of {sorted(valid_tiers)}, "
            f"got {tier_value!r}"
        )
    return Specification(
        spec_id=str(_require(d, "spec_id", where)),
        description=str(_require(d, "description", where)),
        refines_requirement=str(_require(d, "refines_requirement", where)),
        enforcement_tier=tier_value,  # type: ignore[arg-type]
        enforcement_modules=_tuple_of_str(d.get("enforcement_modules", ()), where),
    )


def _build_mcp_label(d: Mapping[str, Any]) -> MCPLabel:
    where = "mcp_label"
    extra = d.get("extra")
    if extra is not None and not isinstance(extra, Mapping):
        raise StpaManifestValidationError(f"{where}: extra must be a mapping")
    return MCPLabel(
        tool_name=str(_require(d, "tool_name", where)),
        capabilities=_tuple_of_str(d.get("capabilities", ()), where),
        confidentiality=str(d.get("confidentiality", "unknown")),
        trust=str(d.get("trust", "unknown")),
        extra={str(k): str(v) for k, v in extra.items()} if extra else None,
    )


# ---------------------------------------------------------------------------
# Coverage matrix
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class StpaCoverageMatrix:
    """
    Mapping from each UCA to the Tex defense modules that mitigate it.

    The matrix is constructed by walking, for each UCA:

      1. All LossScenarios with related_uca == uca_id; collect their
         mitigation_modules into the UCA's module set.
      2. All Hazards in the UCA's related_hazards; for each hazard,
         find Requirements whose addresses_hazards contains it; for
         each requirement, find Specifications that refine it; collect
         the spec's enforcement_modules.

    Step 1 is the direct mitigation chain; step 2 is the
    requirement/specification chain from Doshi-2026.

    Attributes
    ----------
    uca_to_modules:
        Mapping uca_id -> tuple of module names. Modules are
        deduplicated and sorted.
    uncovered_ucas:
        Tuple of uca_ids with zero mitigations across both chains.
    module_to_ucas:
        Reverse mapping: module name -> tuple of uca_ids it mitigates.
    """

    uca_to_modules: dict[str, tuple[str, ...]]
    uncovered_ucas: tuple[str, ...]
    module_to_ucas: dict[str, tuple[str, ...]]


def build_coverage_matrix(manifest: StpaManifest) -> StpaCoverageMatrix:
    """Build a coverage matrix from a validated manifest."""
    # Index helpers.
    scenarios_by_uca: dict[str, list[LossScenario]] = {}
    for ls in manifest.loss_scenarios:
        scenarios_by_uca.setdefault(ls.related_uca, []).append(ls)

    requirements_by_hazard: dict[str, list[Requirement]] = {}
    for r in manifest.requirements:
        for h in r.addresses_hazards:
            requirements_by_hazard.setdefault(h, []).append(r)

    specs_by_requirement: dict[str, list[Specification]] = {}
    for s in manifest.specifications:
        specs_by_requirement.setdefault(s.refines_requirement, []).append(s)

    uca_to_modules: dict[str, tuple[str, ...]] = {}
    uncovered: list[str] = []

    for uca in manifest.unsafe_control_actions:
        modules: set[str] = set()
        # Path 1: direct LossScenario mitigations.
        for ls in scenarios_by_uca.get(uca.uca_id, ()):
            modules.update(ls.mitigation_modules)
        # Path 2: through hazards -> requirements -> specifications.
        for hazard_id in uca.related_hazards:
            for req in requirements_by_hazard.get(hazard_id, ()):
                for spec in specs_by_requirement.get(req.requirement_id, ()):
                    modules.update(spec.enforcement_modules)

        sorted_modules = tuple(sorted(modules))
        uca_to_modules[uca.uca_id] = sorted_modules
        if not sorted_modules:
            uncovered.append(uca.uca_id)

    # Build reverse index.
    module_to_ucas: dict[str, set[str]] = {}
    for uca_id, modules_tuple in uca_to_modules.items():
        for m in modules_tuple:
            module_to_ucas.setdefault(m, set()).add(uca_id)

    matrix = StpaCoverageMatrix(
        uca_to_modules=uca_to_modules,
        uncovered_ucas=tuple(sorted(uncovered)),
        module_to_ucas={m: tuple(sorted(s)) for m, s in module_to_ucas.items()},
    )
    telemetry.emit_event(
        "stpa.coverage.computed",
        level=logging.INFO,
        n_ucas=len(uca_to_modules),
        n_uncovered=len(uncovered),
        n_modules=len(module_to_ucas),
    )
    return matrix
