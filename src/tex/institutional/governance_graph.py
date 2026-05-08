"""
Governance graph.

A labeled transition system (LTS) over institutional states. Per arxiv
2601.10599 §5.4 the formal triple is G = (Q, E, δ) where:
  Q = discrete institutional states (e.g. active, warning, fined,
      credited, suspended)
  E = directed edges (legal transitions) carrying stable join identifiers
      (edge_keys) of the form "<RULE_ID>:<from>-><to>"
  δ : Q x Σ -> Q is the transition function from state-signal pairs to
      successor states, where Σ is the set of observable behavioural
      signals emitted by the Oracle.

The manifest is the public contract per arxiv 2601.11369 §4.2 — a
machine-readable JSON/YAML artifact that externalises the institution.
Two SHA-256 digests are recorded per emitted manifest (Appendix D):
  manifest_semantic_sha256 — canonicalised content (regime identity)
  manifest_file_sha256     — exact emitted bytes (artifact provenance)

The semantic digest excludes the digests themselves and any signature
fields so the manifest can carry its own identity.

Reference
---------
arxiv 2601.11369 (Bracale Syrnikov et al., 2026), Appendix D
arxiv 2601.10599 (Pierucci et al., 2026), §5.4 "The Governance Graph"

Priority: P1.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from tex.institutional.sanctions import (
    RestorativePath,
    Sanction,
    validate_restorative_path,
    validate_sanction,
)
from tex.observability.telemetry import emit_event


# Paper-canonical state labels per arxiv 2601.11369 Figure 2 / Section 4.2.
# We do not hardcode these into validation — manifests are domain-portable
# (Section 4.2 "Domain portability") — but we expose them as a constant so
# fixtures can import the canonical Cournot topology.
CANONICAL_COURNOT_STATES: tuple[str, ...] = (
    "active",
    "warning",
    "fined",
    "credited",
    "suspended",
)

# Edge-key format from Appendix D:  "<RULE_ID>:<from_state>-><to_state>"
# RULE_ID is the stable ABDICO identifier (§4.1, e.g. P2_independent_decision).
_EDGE_KEY_RE = re.compile(
    r"^(?P<rule_id>[A-Za-z0-9_]+):(?P<from>[a-z_][a-z0-9_]*)->(?P<to>[a-z_][a-z0-9_]*)$"
)


@dataclass(frozen=True, slots=True)
class LegalState:
    """
    A discrete institutional state per arxiv 2601.10599 §5.4.

    Fields
    ------
    state_id
        Stable lowercase identifier (e.g. "active", "warning").
    description
        Human-legible label rendered into Institutional notices
        (Appendix C of 2601.11369).
    predicate_ltl
        DEPRECATED. The paper does not use LTL formulas — institutional
        states are discrete labels. Retained as an optional free-text
        annotation for backward compatibility with the original scaffold.
        Setting this has no semantic effect; the Oracle dispatches by
        state_id only.

    TODO(P2): if a future paper extends Institutional AI with LTL-style
        runtime predicates over ecosystem state, repurpose this field.
    """

    state_id: str
    predicate_ltl: str = ""
    description: str = ""


@dataclass(frozen=True, slots=True)
class LegalTransition:
    """
    A manifest-declared edge in the LTS.

    Fields
    ------
    from_state, to_state
        Source and target state_ids. Both must resolve to a declared
        LegalState in the same GovernanceGraph.
    triggered_by
        The EventKind (or Oracle case kind) whose emission requests
        traversal. Examples: "agent_invokes_tool", "probable_violation",
        "expiry_tick". The Controller looks up edges by (from_state,
        triggered_by).
    edge_key
        Stable join identifier per Appendix D. Format:
        "<RULE_ID>:<from_state>-><to_state>". Mandatory and unique within
        the graph.
    rule_id
        ABDICO rule identifier (§4.1). Multiple edges may share a rule_id
        when one rule fans out to several transitions (e.g. one rule
        firing both Active->Warning and Warning->Fined depending on
        prior state).
    sanction_id
        References Sanction.sanction_id. None means a legal transition
        with no penalty (e.g. an expiry restoration).
    restorative_path_id
        References RestorativePath.path_id. Set on restorative edges
        (warning->active, fined->credited, fined->active, etc.).
    timing
        Manifest execution-contract timing per §6.2.2:
          duration_rounds  - how long the target state persists
          cooldown_rounds  - how long before this edge can fire again
          jitter_rounds    - randomised delay (Appendix D contracts.timing)
        None values mean "not declared" and the Controller treats them
        as zero.
    sanction_on_violation
        DEPRECATED alias for sanction_id, retained for back-compat with
        the original scaffold. If both are set they must agree.
    precondition_ltl
        DEPRECATED — see LegalState.predicate_ltl. Retained as a free-
        text annotation field.
    metadata
        Manifest-declared opaque metadata per Appendix D
        ("metadata: tier/tags/provenance"). Carried verbatim.
    """

    from_state: str
    to_state: str
    triggered_by: str
    edge_key: str = ""
    rule_id: str = ""
    sanction_id: str | None = None
    restorative_path_id: str | None = None
    timing: dict[str, int] | None = None
    sanction_on_violation: str | None = None  # deprecated alias
    precondition_ltl: str = ""  # deprecated
    metadata: dict[str, Any] | None = None

    def effective_sanction_id(self) -> str | None:
        """Resolve the sanction_id, accepting the deprecated alias."""
        if self.sanction_id is not None and self.sanction_on_violation is not None:
            if self.sanction_id != self.sanction_on_violation:
                raise ValueError(
                    f"transition {self.edge_key!r} has conflicting sanction_id "
                    f"({self.sanction_id!r}) and sanction_on_violation "
                    f"({self.sanction_on_violation!r})"
                )
            return self.sanction_id
        return self.sanction_id or self.sanction_on_violation


class GovernanceGraphValidationError(ValueError):
    """Raised when a manifest fails structural validation."""


@dataclass(frozen=True, slots=True)
class GovernanceGraph:
    """
    A public, immutable governance manifest.

    Construction
    ------------
    Use the classmethods rather than the constructor directly:
      GovernanceGraph.from_dict(data)
      GovernanceGraph.from_json(text)
      GovernanceGraph.from_yaml(text_or_path)

    Each classmethod:
      1. validates the topology (state references, edge_key uniqueness,
         sanction/path resolution, edge_key regex)
      2. computes manifest_semantic_sha256 over the canonicalised content
         (states, transitions, sanctions, restorative_paths, policy_surface,
         contracts) excluding the digest fields and any signature
      3. computes manifest_file_sha256 over the raw bytes when loaded
         from a file (or recomputes it from a deterministic re-serialise
         when constructed from a dict)

    Public verification
    -------------------
    The semantic_digest_input() method returns the dict that gets hashed.
    Auditors verify regime identity by recomputing canonical_sha256 over
    this dict and comparing against manifest_semantic_sha256.

    Reference
    ---------
    arxiv 2601.11369 Appendix D (manifest schema, two-digest scheme)
    arxiv 2601.10599 §5.4 (graph topology + manifest + governance engine)

    TODO(P2): policy_program IR (currently carried as opaque dict) becomes
        a typed CST when we ship a manifest interpreter spec.
    TODO(P2): publisher_signature_b64 is currently optional and unverified
        by GovernanceGraph itself; downstream code (GovernanceLog) signs
        decisions but the manifest itself is not signed in Thread 12.
    """

    graph_id: str
    version: str
    states: tuple[LegalState, ...]
    transitions: tuple[LegalTransition, ...]
    sanctions: tuple[Sanction, ...]
    restorative_paths: tuple[RestorativePath, ...]
    manifest_hash: str = ""  # back-compat alias for manifest_semantic_sha256
    publisher_signature_b64: str = ""
    manifest_semantic_sha256: str = ""
    manifest_file_sha256: str = ""
    schema_version: str = "v1"
    interpreter_name: str = "tex.institutional.oracle_controller"
    interpreter_version: str = "1.0.0"
    policy_surface: dict[str, Any] | None = None
    policy_program: dict[str, Any] | None = None
    contracts: dict[str, Any] | None = None

    # ------------------------------------------------------------------
    # Constructors
    # ------------------------------------------------------------------

    @classmethod
    def from_dict(
        cls,
        data: dict[str, Any],
        *,
        file_bytes: bytes | None = None,
    ) -> "GovernanceGraph":
        """
        Build a GovernanceGraph from a parsed manifest dict.

        Parameters
        ----------
        data
            Parsed manifest (typically ``json.load`` or ``yaml.safe_load``
            output). Schema follows Appendix D.
        file_bytes
            Optional raw bytes for the manifest_file_sha256 digest. If
            omitted, a deterministic re-serialisation is hashed instead
            so the field always has a value.

        Raises
        ------
        GovernanceGraphValidationError
            If the manifest is structurally invalid.
        """
        graph_id = _required_str(data, "graph_id")
        version = _required_str(data, "version")
        schema_version = str(data.get("schema_version", "v1"))

        interpreter = data.get("interpreter") or {}
        interpreter_name = str(
            interpreter.get("name", "tex.institutional.oracle_controller")
        )
        interpreter_version = str(interpreter.get("version", "1.0.0"))

        states = _parse_states(data.get("states") or [])
        sanctions = _parse_sanctions(data.get("sanctions") or [])
        restorative_paths = _parse_restorative_paths(
            data.get("restorative_paths") or []
        )
        transitions = _parse_transitions(data.get("transitions") or [])

        # Carry policy_surface / policy_program / contracts verbatim. The
        # paper specifies these as opaque (versioned IR + resolved snapshot)
        # so we do not parse them into typed structures yet.
        policy_surface = (
            dict(data["policy_surface"])
            if isinstance(data.get("policy_surface"), dict)
            else None
        )
        policy_program = (
            dict(data["policy_program"])
            if isinstance(data.get("policy_program"), dict)
            else None
        )
        contracts = (
            dict(data["contracts"])
            if isinstance(data.get("contracts"), dict)
            else None
        )

        publisher_signature_b64 = str(data.get("publisher_signature_b64", ""))

        # ----------------------------------------------------------------
        # Validate references and edge-key well-formedness BEFORE hashing
        # so the digest is only computed for structurally valid manifests.
        # ----------------------------------------------------------------
        _validate_topology(
            states=states,
            transitions=transitions,
            sanctions=sanctions,
            restorative_paths=restorative_paths,
        )

        # Compute the semantic digest over canonical content.
        semantic_input = _semantic_digest_input(
            graph_id=graph_id,
            version=version,
            schema_version=schema_version,
            interpreter_name=interpreter_name,
            interpreter_version=interpreter_version,
            states=states,
            transitions=transitions,
            sanctions=sanctions,
            restorative_paths=restorative_paths,
            policy_surface=policy_surface,
            policy_program=policy_program,
            contracts=contracts,
        )
        # Lazy import to avoid triggering tex.events.__init__ which has an
        # internal circular dependency with tex.ecosystem at module-load
        # time. Runtime tests resolve fine because something always loads
        # tex.ecosystem first; institutional must not assume that.
        from tex.events._canonical import canonical_json, sha256_hex

        semantic_digest = sha256_hex(canonical_json(semantic_input))

        # File digest covers the bytes the auditor actually saw. For exact
        # byte-level provenance we hash the raw bytes directly (sha256_hex
        # only takes UTF-8 strings, which would silently re-encode).
        if file_bytes is not None:
            import hashlib

            file_digest = hashlib.sha256(file_bytes).hexdigest()
        else:
            # No file bytes supplied — deterministic re-serialise so the
            # field is always populated. In this mode the file digest
            # equals the semantic digest.
            file_digest = semantic_digest

        graph = cls(
            graph_id=graph_id,
            version=version,
            states=states,
            transitions=transitions,
            sanctions=sanctions,
            restorative_paths=restorative_paths,
            manifest_hash=semantic_digest,  # back-compat alias
            publisher_signature_b64=publisher_signature_b64,
            manifest_semantic_sha256=semantic_digest,
            manifest_file_sha256=file_digest,
            schema_version=schema_version,
            interpreter_name=interpreter_name,
            interpreter_version=interpreter_version,
            policy_surface=policy_surface,
            policy_program=policy_program,
            contracts=contracts,
        )

        emit_event(
            "institutional.governance_graph.loaded",
            graph_id=graph_id,
            version=version,
            num_states=len(states),
            num_transitions=len(transitions),
            num_sanctions=len(sanctions),
            num_restorative_paths=len(restorative_paths),
            manifest_semantic_sha256=semantic_digest,
        )
        return graph

    @classmethod
    def from_json(cls, text: str | bytes) -> "GovernanceGraph":
        """Build from a JSON manifest string (or raw bytes)."""
        if isinstance(text, bytes):
            file_bytes = text
            data = json.loads(text.decode("utf-8"))
        else:
            file_bytes = text.encode("utf-8")
            data = json.loads(text)
        if not isinstance(data, dict):
            raise GovernanceGraphValidationError(
                f"top-level manifest must be a JSON object, got {type(data).__name__}"
            )
        return cls.from_dict(data, file_bytes=file_bytes)

    @classmethod
    def from_yaml(cls, source: str | Path | bytes) -> "GovernanceGraph":
        """
        Build from a YAML manifest. Accepts a file path, a YAML string,
        or raw bytes.

        PyYAML is imported lazily. It is transitively present via
        ``uvicorn[standard]`` in the existing requirements.txt, but not
        an explicit dependency. If the import fails the caller gets a
        clear actionable error.

        TODO(P1): declare PyYAML as an explicit dependency once a thread
            owner approves; or replace with stdlib JSON if YAML is dropped.
        """
        try:
            import yaml  # type: ignore[import-not-found]
        except ImportError as exc:
            raise GovernanceGraphValidationError(
                "PyYAML is required to load YAML manifests. "
                "Install via: pip install pyyaml — or use from_json instead."
            ) from exc

        if isinstance(source, Path):
            file_bytes = source.read_bytes()
            data = yaml.safe_load(file_bytes)
        elif isinstance(source, bytes):
            file_bytes = source
            data = yaml.safe_load(source)
        else:
            # str: could be a path or inline YAML. Disambiguate by
            # checking for a YAML structural character on the first line.
            candidate_path = Path(source)
            if (
                "\n" not in source
                and len(source) < 4096
                and candidate_path.exists()
                and candidate_path.is_file()
            ):
                file_bytes = candidate_path.read_bytes()
                data = yaml.safe_load(file_bytes)
            else:
                file_bytes = source.encode("utf-8")
                data = yaml.safe_load(source)

        if not isinstance(data, dict):
            raise GovernanceGraphValidationError(
                f"top-level manifest must be a YAML mapping, got {type(data).__name__}"
            )
        return cls.from_dict(data, file_bytes=file_bytes)

    # ------------------------------------------------------------------
    # Read helpers
    # ------------------------------------------------------------------

    def lookup_state(self, state_id: str) -> LegalState:
        """Return the LegalState with the given id or raise KeyError."""
        for s in self.states:
            if s.state_id == state_id:
                return s
        raise KeyError(f"no LegalState with state_id={state_id!r}")

    def lookup_sanction(self, sanction_id: str) -> Sanction:
        """Return the Sanction with the given id or raise KeyError."""
        for s in self.sanctions:
            if s.sanction_id == sanction_id:
                return s
        raise KeyError(f"no Sanction with sanction_id={sanction_id!r}")

    def lookup_restorative_path(self, path_id: str) -> RestorativePath:
        """Return the RestorativePath with the given id or raise KeyError."""
        for p in self.restorative_paths:
            if p.path_id == path_id:
                return p
        raise KeyError(f"no RestorativePath with path_id={path_id!r}")

    def find_transition(
        self,
        *,
        from_state: str,
        triggered_by: str,
    ) -> LegalTransition | None:
        """
        Return the unique transition matching (from_state, triggered_by),
        or None if no manifest-declared edge fits. Raises ValueError if
        the manifest declares more than one (which would be ambiguous —
        topology validation prevents this but defence-in-depth here).
        """
        matches = [
            t
            for t in self.transitions
            if t.from_state == from_state and t.triggered_by == triggered_by
        ]
        if not matches:
            return None
        if len(matches) > 1:
            raise ValueError(
                f"ambiguous transitions for from_state={from_state!r} "
                f"triggered_by={triggered_by!r}: "
                f"{[m.edge_key for m in matches]}"
            )
        return matches[0]

    def find_transition_by_edge_key(
        self, edge_key: str
    ) -> LegalTransition | None:
        """Look up by stable join identifier."""
        for t in self.transitions:
            if t.edge_key == edge_key:
                return t
        return None

    def enabled_transitions(self, from_state: str) -> tuple[LegalTransition, ...]:
        """All transitions outgoing from ``from_state``."""
        return tuple(t for t in self.transitions if t.from_state == from_state)

    def semantic_digest_input(self) -> dict[str, Any]:
        """
        Return the canonical content dict the auditor must hash to
        re-derive manifest_semantic_sha256.
        """
        return _semantic_digest_input(
            graph_id=self.graph_id,
            version=self.version,
            schema_version=self.schema_version,
            interpreter_name=self.interpreter_name,
            interpreter_version=self.interpreter_version,
            states=self.states,
            transitions=self.transitions,
            sanctions=self.sanctions,
            restorative_paths=self.restorative_paths,
            policy_surface=self.policy_surface,
            policy_program=self.policy_program,
            contracts=self.contracts,
        )


# ----------------------------------------------------------------------
# Parsing helpers
# ----------------------------------------------------------------------


def _required_str(data: dict[str, Any], key: str) -> str:
    if key not in data or not isinstance(data[key], str) or not data[key]:
        raise GovernanceGraphValidationError(
            f"manifest is missing required string field {key!r}"
        )
    return data[key]


def _parse_states(raw: Iterable[Any]) -> tuple[LegalState, ...]:
    out: list[LegalState] = []
    for entry in raw:
        if isinstance(entry, str):
            # Shorthand: bare string means {state_id: <str>}
            out.append(LegalState(state_id=entry))
            continue
        if not isinstance(entry, dict):
            raise GovernanceGraphValidationError(
                f"state entry must be a string or mapping, got {type(entry).__name__}"
            )
        state_id = entry.get("state_id") or entry.get("id")
        if not isinstance(state_id, str) or not state_id:
            raise GovernanceGraphValidationError(
                f"state entry missing state_id: {entry!r}"
            )
        out.append(
            LegalState(
                state_id=state_id,
                description=str(entry.get("description", "")),
                predicate_ltl=str(entry.get("predicate_ltl", "")),
            )
        )
    return tuple(out)


def _parse_sanctions(raw: Iterable[Any]) -> tuple[Sanction, ...]:
    out: list[Sanction] = []
    for entry in raw:
        if not isinstance(entry, dict):
            raise GovernanceGraphValidationError(
                f"sanction entry must be a mapping, got {type(entry).__name__}"
            )
        sanction = Sanction(
            sanction_id=str(entry.get("sanction_id", "")),
            description=str(entry.get("description", "")),
            cost_to_actor=float(entry.get("cost_to_actor", 0.0)),
            cost_to_system=float(entry.get("cost_to_system", 0.0)),
            enforcement_action=str(entry.get("enforcement_action", "")),
            tier=_optional_int(entry, "tier"),
            fine_rate=_optional_float(entry, "fine_rate"),
            fine_floor=_optional_float(entry, "fine_floor"),
            duration_rounds=_optional_int(entry, "duration_rounds"),
        )
        try:
            validate_sanction(sanction)
        except ValueError as exc:
            raise GovernanceGraphValidationError(
                f"invalid sanction {sanction.sanction_id!r}: {exc}"
            ) from exc
        out.append(sanction)
    return tuple(out)


def _parse_restorative_paths(raw: Iterable[Any]) -> tuple[RestorativePath, ...]:
    out: list[RestorativePath] = []
    for entry in raw:
        if not isinstance(entry, dict):
            raise GovernanceGraphValidationError(
                f"restorative_path entry must be a mapping, got {type(entry).__name__}"
            )
        path = RestorativePath(
            path_id=str(entry.get("path_id", "")),
            description=str(entry.get("description", "")),
            restorative_event_kinds=tuple(entry.get("restorative_event_kinds", ())),
            target_legal_state_id=str(entry.get("target_legal_state_id", "")),
            restoration_kind=str(entry.get("restoration_kind", "expiry")),
            condition=(
                dict(entry["condition"])
                if isinstance(entry.get("condition"), dict)
                else None
            ),
        )
        try:
            validate_restorative_path(path)
        except ValueError as exc:
            raise GovernanceGraphValidationError(
                f"invalid restorative_path {path.path_id!r}: {exc}"
            ) from exc
        out.append(path)
    return tuple(out)


def _parse_transitions(raw: Iterable[Any]) -> tuple[LegalTransition, ...]:
    out: list[LegalTransition] = []
    for entry in raw:
        if not isinstance(entry, dict):
            raise GovernanceGraphValidationError(
                f"transition entry must be a mapping, got {type(entry).__name__}"
            )
        from_state = str(entry.get("from_state", ""))
        to_state = str(entry.get("to_state", ""))
        edge_key = str(entry.get("edge_key", ""))
        rule_id = str(entry.get("rule_id", ""))

        # Auto-derive edge_key if rule_id+from+to are present but edge_key
        # is missing — paper format is mechanical so we can do this safely.
        if not edge_key and rule_id and from_state and to_state:
            edge_key = f"{rule_id}:{from_state}->{to_state}"
        # Auto-derive rule_id from edge_key if only edge_key is given.
        if edge_key and not rule_id:
            m = _EDGE_KEY_RE.match(edge_key)
            if m is not None:
                rule_id = m.group("rule_id")

        timing_raw = entry.get("timing")
        timing: dict[str, int] | None = None
        if isinstance(timing_raw, dict):
            timing = {k: int(v) for k, v in timing_raw.items() if v is not None}

        sanction_id = entry.get("sanction_id") or entry.get("sanction_on_violation")
        sanction_id_str: str | None = (
            str(sanction_id) if sanction_id is not None else None
        )
        restorative_path_id = entry.get("restorative_path_id")
        restorative_path_id_str: str | None = (
            str(restorative_path_id) if restorative_path_id is not None else None
        )

        out.append(
            LegalTransition(
                from_state=from_state,
                to_state=to_state,
                triggered_by=str(entry.get("triggered_by", "")),
                edge_key=edge_key,
                rule_id=rule_id,
                sanction_id=sanction_id_str,
                restorative_path_id=restorative_path_id_str,
                timing=timing,
                metadata=(
                    dict(entry["metadata"])
                    if isinstance(entry.get("metadata"), dict)
                    else None
                ),
            )
        )
    return tuple(out)


def _optional_int(entry: dict[str, Any], key: str) -> int | None:
    v = entry.get(key)
    return int(v) if v is not None else None


def _optional_float(entry: dict[str, Any], key: str) -> float | None:
    v = entry.get(key)
    return float(v) if v is not None else None


# ----------------------------------------------------------------------
# Validation
# ----------------------------------------------------------------------


def _validate_topology(
    *,
    states: tuple[LegalState, ...],
    transitions: tuple[LegalTransition, ...],
    sanctions: tuple[Sanction, ...],
    restorative_paths: tuple[RestorativePath, ...],
) -> None:
    """Enforce the manifest's structural invariants."""
    if not states:
        raise GovernanceGraphValidationError("manifest declares no states")

    state_ids = {s.state_id for s in states}
    if len(state_ids) != len(states):
        raise GovernanceGraphValidationError("duplicate state_id in manifest")

    sanction_ids = {s.sanction_id for s in sanctions}
    path_ids = {p.path_id for p in restorative_paths}

    seen_edge_keys: set[str] = set()
    seen_state_event_pairs: set[tuple[str, str]] = set()

    for t in transitions:
        # Edge key must be present and well-formed.
        if not t.edge_key:
            raise GovernanceGraphValidationError(
                f"transition {t.from_state}->{t.to_state} missing edge_key"
            )
        m = _EDGE_KEY_RE.match(t.edge_key)
        if m is None:
            raise GovernanceGraphValidationError(
                f"transition edge_key {t.edge_key!r} does not match "
                f"<RULE_ID>:<from>-><to> format"
            )
        if m.group("from") != t.from_state or m.group("to") != t.to_state:
            raise GovernanceGraphValidationError(
                f"transition edge_key {t.edge_key!r} disagrees with "
                f"declared from_state={t.from_state!r}/to_state={t.to_state!r}"
            )
        if t.rule_id and m.group("rule_id") != t.rule_id:
            raise GovernanceGraphValidationError(
                f"transition edge_key {t.edge_key!r} has rule_id "
                f"{m.group('rule_id')!r} but field rule_id={t.rule_id!r}"
            )

        if t.edge_key in seen_edge_keys:
            raise GovernanceGraphValidationError(
                f"duplicate edge_key {t.edge_key!r}"
            )
        seen_edge_keys.add(t.edge_key)

        # State references must resolve.
        if t.from_state not in state_ids:
            raise GovernanceGraphValidationError(
                f"transition {t.edge_key!r} references unknown from_state "
                f"{t.from_state!r}"
            )
        if t.to_state not in state_ids:
            raise GovernanceGraphValidationError(
                f"transition {t.edge_key!r} references unknown to_state "
                f"{t.to_state!r}"
            )

        # triggered_by must be set.
        if not t.triggered_by:
            raise GovernanceGraphValidationError(
                f"transition {t.edge_key!r} missing triggered_by"
            )

        # Resolve sanction_id / sanction_on_violation alias (may raise).
        try:
            eff_sanction = t.effective_sanction_id()
        except ValueError as exc:
            raise GovernanceGraphValidationError(str(exc)) from exc
        if eff_sanction is not None and eff_sanction not in sanction_ids:
            raise GovernanceGraphValidationError(
                f"transition {t.edge_key!r} references unknown sanction_id "
                f"{eff_sanction!r}"
            )

        if (
            t.restorative_path_id is not None
            and t.restorative_path_id not in path_ids
        ):
            raise GovernanceGraphValidationError(
                f"transition {t.edge_key!r} references unknown "
                f"restorative_path_id {t.restorative_path_id!r}"
            )

        # The Controller dispatches by (from_state, triggered_by). Two
        # transitions sharing that pair would be ambiguous.
        pair = (t.from_state, t.triggered_by)
        if pair in seen_state_event_pairs:
            raise GovernanceGraphValidationError(
                f"two transitions share (from_state={t.from_state!r}, "
                f"triggered_by={t.triggered_by!r}) — Controller dispatch "
                f"would be ambiguous"
            )
        seen_state_event_pairs.add(pair)

    # Restorative paths must target a real state.
    for p in restorative_paths:
        if p.target_legal_state_id not in state_ids:
            raise GovernanceGraphValidationError(
                f"restorative_path {p.path_id!r} targets unknown state "
                f"{p.target_legal_state_id!r}"
            )


# ----------------------------------------------------------------------
# Semantic digest input
# ----------------------------------------------------------------------


def _semantic_digest_input(
    *,
    graph_id: str,
    version: str,
    schema_version: str,
    interpreter_name: str,
    interpreter_version: str,
    states: tuple[LegalState, ...],
    transitions: tuple[LegalTransition, ...],
    sanctions: tuple[Sanction, ...],
    restorative_paths: tuple[RestorativePath, ...],
    policy_surface: dict[str, Any] | None,
    policy_program: dict[str, Any] | None,
    contracts: dict[str, Any] | None,
) -> dict[str, Any]:
    """
    Build the canonical dict that gets hashed to produce
    manifest_semantic_sha256. Per Appendix D this excludes the digest
    fields themselves and any signature so the manifest can carry its
    own identity.
    """
    return {
        "schema_version": schema_version,
        "graph_id": graph_id,
        "version": version,
        "interpreter": {
            "name": interpreter_name,
            "version": interpreter_version,
        },
        "states": [
            {
                "state_id": s.state_id,
                "description": s.description,
                "predicate_ltl": s.predicate_ltl,
            }
            for s in states
        ],
        "transitions": [
            {
                "edge_key": t.edge_key,
                "rule_id": t.rule_id,
                "from_state": t.from_state,
                "to_state": t.to_state,
                "triggered_by": t.triggered_by,
                "sanction_id": t.effective_sanction_id() or "",
                "restorative_path_id": t.restorative_path_id or "",
                "timing": t.timing or {},
                "metadata": _coerce_jsonable(t.metadata or {}),
            }
            for t in transitions
        ],
        "sanctions": [
            {
                "sanction_id": s.sanction_id,
                "description": s.description,
                "cost_to_actor_x1000": int(round(s.cost_to_actor * 1000)),
                "cost_to_system_x1000": int(round(s.cost_to_system * 1000)),
                "enforcement_action": s.enforcement_action,
                "tier": s.tier if s.tier is not None else 0,
                "fine_rate_x1000": (
                    int(round(s.fine_rate * 1000)) if s.fine_rate is not None else 0
                ),
                "fine_floor_x1000": (
                    int(round(s.fine_floor * 1000))
                    if s.fine_floor is not None
                    else 0
                ),
                "duration_rounds": (
                    s.duration_rounds if s.duration_rounds is not None else 0
                ),
            }
            for s in sanctions
        ],
        "restorative_paths": [
            {
                "path_id": p.path_id,
                "description": p.description,
                "restorative_event_kinds": list(p.restorative_event_kinds),
                "target_legal_state_id": p.target_legal_state_id,
                "restoration_kind": p.restoration_kind,
                "condition": _coerce_jsonable(p.condition or {}),
            }
            for p in restorative_paths
        ],
        "policy_surface": _coerce_jsonable(policy_surface or {}),
        "policy_program": _coerce_jsonable(policy_program or {}),
        "contracts": _coerce_jsonable(contracts or {}),
    }


def _coerce_jsonable(value: Any) -> Any:
    """
    Coerce a Python value into the canonical-JSON subset
    (str | int | bool | None | dict[str,...] | list).

    Floats are quantised to milli-units (rounded ints) to satisfy
    tex.events._canonical's "no floats" rule. Tuples are listed.
    Nested structures recurse. Anything else is stringified.
    """
    if value is None or isinstance(value, (str, bool)):
        return value
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        # Quantise to milli-units. Manifest authors who need exact floats
        # should encode them as ints up-front.
        return int(round(value * 1000))
    if isinstance(value, dict):
        return {
            str(k): _coerce_jsonable(v) for k, v in sorted(value.items())
        }
    if isinstance(value, (list, tuple)):
        return [_coerce_jsonable(v) for v in value]
    return str(value)
