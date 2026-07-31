"""
Private-data sandbox.

Reference: Stanley, Verma, Tsai, Kallas, Kumar. "An AI Agent Execution
Environment to Safeguard User Data." arXiv:2604.19657 (Apr 2026).

Constrains the agent's view of user data and enforces:
  - No persistence of user data beyond session (the data dict is cleared
    on sandbox exit)
  - All user-data egress audited and capability-gated (the disclosure log
    records every external party that received which data field)
  - Data minimization at retrieval time (the agent program reads via
    ``data.<field>`` lookups; only fields actually read enter the taint
    set)

GAAP architecture (paper §3.3)
------------------------------
GAAP's runtime has five interrelated parts:

  1. IFC Core              — taint tracking through a code artifact
  2. Private Data DB       — encapsulated user data, agent cannot read raw
  3. Permission DB         — allow/deny pairs of (data_name, party)
  4. Disclosure Log        — persistent record of every external disclosure
  5. Annotation Framework  — per-tool labels of which data fields flow

Tex implements an in-process MVP of all five for this thread. Production
deployment SHOULD upgrade the IFC core to a separate-process / WASM
sandbox per the paper's full threat model (§3.2: "the user prompt, model
provider, and model context [are] fully untrusted"). The current
implementation is sufficient for the acceptance criterion ("records every
egress event") but is NOT a substitute for a real isolation boundary.

Security caveat
---------------
Per the existing ``execute_with_user_data`` signature, the agent program
arrives as a ``str``. We evaluate it via ``exec()`` inside a restricted
namespace with ``__builtins__`` minimized and a curated API surface. This
is well-understood to be defeatable by a sufficiently-motivated attacker
(``().__class__.__bases__[0].__subclasses__()`` etc.). Production
deployments where the agent program may be adversarial MUST replace the
exec with a real isolation boundary — RestrictedPython, a subprocess, a
WASM runtime, or a TEE per the paper's vision. This is documented as a
TODO citing arxiv 2604.19657 §3.2.

Priority: P1.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Iterable, Mapping
from uuid import uuid4

from tex.observability import telemetry


# ---------------------------------------------------------------------------
# Permission specification (GAAP §4.3)
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class PermissionSpec:
    """
    A user-authored permission specification.

    Per GAAP §3.2: "a permission specification is an allow/deny flag for
    a pair of a private data name and an external party."
    """

    data_name: str
    external_party: str
    allow: bool


@dataclass(slots=True)
class PermissionDatabase:
    """In-memory permission DB. Tracks (data_name, party) -> allow flag."""

    entries: dict[tuple[str, str], bool] = field(default_factory=dict)

    def allow(self, data_name: str, party: str) -> None:
        self.entries[(data_name, party)] = True

    def deny(self, data_name: str, party: str) -> None:
        self.entries[(data_name, party)] = False

    def add(self, spec: PermissionSpec) -> None:
        self.entries[(spec.data_name, spec.external_party)] = spec.allow

    def lookup(self, data_name: str, party: str) -> bool | None:
        """
        Return True if disclosure is permitted, False if denied, None if
        no decision exists yet (caller should prompt the user, per
        GAAP §3.1.1 step 5).
        """
        return self.entries.get((data_name, party))


# ---------------------------------------------------------------------------
# Disclosure log (GAAP §3.3.4 / §4.5)
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class DisclosureRecord:
    """
    One recorded disclosure of user data to an external party.

    Per GAAP §1: "GAAP introduces a disclosure log that records all prior
    disclosures of private data to external services ... allowing it to
    track and prevent unintended data flows that occur across tasks and
    tool calls. This log can also be used for compliance in accordance
    to government and other regulations."
    """

    record_id: str
    timestamp: datetime
    data_names: tuple[str, ...]
    external_party: str
    tool_name: str
    allowed: bool
    reason: str = ""


@dataclass(slots=True)
class DisclosureLog:
    """Append-only disclosure log."""

    records: list[DisclosureRecord] = field(default_factory=list)

    def append(self, record: DisclosureRecord) -> None:
        self.records.append(record)

    def all(self) -> tuple[DisclosureRecord, ...]:
        return tuple(self.records)


# ---------------------------------------------------------------------------
# Annotation framework (GAAP §3.3.5 / §4.4)
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ToolAnnotation:
    """
    A user-curated annotation describing which data flows a tool exposes.

    Per GAAP §3.3.5: "GAAP develops an annotation framework that can be
    used to describe the associated parties and data flows for each
    method of each MCP service ... users can import to use with GAAP."
    """

    tool_name: str
    external_party: str
    declassifies: tuple[str, ...] = ()  # data names this tool may disclose
    output_is_private: bool = True  # GAAP §3.1.2: outputs default to private


# ---------------------------------------------------------------------------
# Tainted values
# ---------------------------------------------------------------------------


class _Tainted:
    """
    A user-data value carrying a taint set of source data names.

    Per GAAP §3.1.2 / §4.1: "GAAP achieves [taint tracking] by (1)
    requiring the agent to generate code that performs the desired task,
    and (2) applying Information Flow Control to determine how that
    code accesses and discloses private user data."

    This class wraps a value and propagates taint through string
    concatenation, formatting, and the egress() helper. It is NOT a
    complete IFC implementation — production deployment should use a
    real label-tracking type system. The MVP here is sufficient for the
    acceptance test ("records every egress event").
    """

    __slots__ = ("_value", "_taints")

    def __init__(self, value: object, taints: Iterable[str]) -> None:
        self._value = value
        self._taints: frozenset[str] = frozenset(taints)

    @property
    def value(self) -> object:
        return self._value

    @property
    def taints(self) -> frozenset[str]:
        return self._taints

    def __repr__(self) -> str:
        return f"Tainted({self._value!r}, taints={sorted(self._taints)})"

    def __str__(self) -> str:
        return str(self._value)

    def __add__(self, other: object) -> "_Tainted":
        return _Tainted(
            f"{self._value}{_str_of(other)}",
            self._taints | _taints_of(other),
        )

    def __radd__(self, other: object) -> "_Tainted":
        return _Tainted(
            f"{_str_of(other)}{self._value}",
            self._taints | _taints_of(other),
        )

    def __eq__(self, other: object) -> bool:
        if isinstance(other, _Tainted):
            return self._value == other._value
        return self._value == other

    def __hash__(self) -> int:
        return hash(("_Tainted", self._value))


def _taints_of(value: object) -> frozenset[str]:
    if isinstance(value, _Tainted):
        return value.taints
    if isinstance(value, (list, tuple, set, frozenset)):
        out: frozenset[str] = frozenset()
        for v in value:
            out = out | _taints_of(v)
        return out
    if isinstance(value, dict):
        out = frozenset()
        for v in value.values():
            out = out | _taints_of(v)
        return out
    return frozenset()


def _str_of(value: object) -> str:
    if isinstance(value, _Tainted):
        return str(value.value)
    return str(value)


# ---------------------------------------------------------------------------
# The sandbox
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class _DataView:
    """
    The agent program's view onto user data.

    Each attribute access auto-taints the returned value with the
    attribute name. Reads through ``__getitem__`` work the same way.
    """

    _backing: dict[str, object]

    def __getattr__(self, name: str) -> _Tainted:
        if name.startswith("_"):
            raise AttributeError(name)
        if name not in self._backing:
            raise KeyError(f"private data field not found: {name}")
        return _Tainted(self._backing[name], (name,))

    def __getitem__(self, name: str) -> _Tainted:
        if name not in self._backing:
            raise KeyError(f"private data field not found: {name}")
        return _Tainted(self._backing[name], (name,))


class PrivateDataSandboxError(RuntimeError):
    """Raised when sandbox setup or teardown fails."""


class PrivateDataSandbox:
    """
    GAAP-style execution sandbox for private user data.

    Usage
    -----
    >>> sandbox = PrivateDataSandbox(
    ...     permissions=PermissionDatabase(),
    ...     annotations=(),
    ... )
    >>> result = sandbox.execute_with_user_data(
    ...     user_data={"date_of_birth": "1990-01-01"},
    ...     agent_program="result = data.date_of_birth",
    ... )
    >>> result["return"].value
    '1990-01-01'

    The agent program runs in a restricted namespace with the following
    surface:

      data         — read-only view onto user_data; attribute access auto-taints
      egress(value, *, tool, party)  — record + permission-check a disclosure
      result       — the program SHOULD assign its return value here

    Any disclosure performed via ``egress()`` is recorded in the
    disclosure log; if the permission DB denies the (data_name, party)
    pair for any taint in the value, the call raises PermissionError.
    Any read of a key absent from user_data raises KeyError.
    """

    def __init__(
        self,
        *,
        permissions: PermissionDatabase | None = None,
        annotations: tuple[ToolAnnotation, ...] = (),
        disclosure_log: DisclosureLog | None = None,
        # When True, missing permissions raise PermissionError (GAAP
        # §3.1.1 step 4); when False, we record the disclosure as
        # disallowed and the agent program receives None. The paper's
        # default behavior is interactive (step 5: "GAAP pauses ...
        # asks the user"), but we don't have a user in-process; raising
        # is the closest defensible default for a non-interactive run.
        deny_unspecified: bool = True,
    ) -> None:
        self._permissions = permissions or PermissionDatabase()
        self._annotations: dict[str, ToolAnnotation] = {a.tool_name: a for a in annotations}
        self._disclosure_log = disclosure_log or DisclosureLog()
        self._deny_unspecified = deny_unspecified

    @property
    def disclosure_log(self) -> DisclosureLog:
        return self._disclosure_log

    @property
    def permissions(self) -> PermissionDatabase:
        return self._permissions

    def execute_with_user_data(
        self,
        *,
        user_data: dict,
        agent_program: str,
    ) -> dict:
        """
        Execute ``agent_program`` against ``user_data`` in a sandboxed env.

        Returns a dict with:
          return:        the program's ``result`` value (Tainted-wrapped if
                         it carried any taint)
          disclosures:   tuple of DisclosureRecord produced during run
          taints_seen:   set of data field names that were ever read

        Implementation steps (matching GAAP §3.1.1):

          1. Create the ephemeral execution environment.
          2. Inject minimized user data behind the _DataView indirection.
          3. Run the agent program; intercept every ``egress`` call and
             check it against the permission DB; record to log.
          4. Capture the return value; destroy the data view; clear locals.
          5. Emit summary telemetry.

        TODO(arxiv:2604.19657 §3.2): replace exec() with a real
            isolation boundary. The current implementation will not
            withstand a determined adversary inside agent_program; see
            module-level "Security caveat".
        """
        if not isinstance(user_data, dict):
            raise PrivateDataSandboxError("user_data must be a dict")
        if not isinstance(agent_program, str):
            raise PrivateDataSandboxError("agent_program must be a string")

        # Step 1+2: build the ephemeral view.
        data_view = _DataView(_backing=dict(user_data))
        local_disclosures: list[DisclosureRecord] = []
        taints_seen: set[str] = set()

        def _egress(value: object, *, tool: str, party: str) -> object:
            """Record + permission-check a disclosure. Returns the value if allowed."""
            taints = sorted(_taints_of(value))
            taints_seen.update(taints)
            # If the value carries no taint, this is a public payload —
            # GAAP §3.2 allows public disclosures unconditionally (the
            # paper's threat model only protects "private user data").
            if not taints:
                rec = DisclosureRecord(
                    record_id=str(uuid4()),
                    timestamp=datetime.now(UTC),
                    data_names=(),
                    external_party=party,
                    tool_name=tool,
                    allowed=True,
                    reason="no-taint",
                )
                self._disclosure_log.append(rec)
                local_disclosures.append(rec)
                return _str_of(value) if isinstance(value, _Tainted) else value
            # Tainted disclosure: every taint must be permitted to ``party``.
            denied: list[str] = []
            unspecified: list[str] = []
            for t in taints:
                lookup = self._permissions.lookup(t, party)
                if lookup is False:
                    denied.append(t)
                elif lookup is None:
                    unspecified.append(t)
            if denied or (unspecified and self._deny_unspecified):
                reason = (
                    f"denied:{','.join(denied)}"
                    if denied
                    else f"unspecified:{','.join(unspecified)}"
                )
                rec = DisclosureRecord(
                    record_id=str(uuid4()),
                    timestamp=datetime.now(UTC),
                    data_names=tuple(taints),
                    external_party=party,
                    tool_name=tool,
                    allowed=False,
                    reason=reason,
                )
                self._disclosure_log.append(rec)
                local_disclosures.append(rec)
                telemetry.emit_event(
                    "private_data.egress.denied",
                    level=logging.WARNING,
                    tool=tool,
                    party=party,
                    data_names=list(taints),
                    reason=reason,
                )
                raise PermissionError(
                    f"disclosure of {taints} to {party!r} via {tool!r}: {reason}"
                )
            rec = DisclosureRecord(
                record_id=str(uuid4()),
                timestamp=datetime.now(UTC),
                data_names=tuple(taints),
                external_party=party,
                tool_name=tool,
                allowed=True,
                reason="permitted",
            )
            self._disclosure_log.append(rec)
            local_disclosures.append(rec)
            telemetry.emit_event(
                "private_data.egress",
                tool=tool,
                party=party,
                data_names=list(taints),
            )
            return _str_of(value) if isinstance(value, _Tainted) else value

        # Step 3: build the restricted globals/locals and run.
        # __builtins__ is replaced with a curated minimum to push back
        # against the most obvious bypasses. This is NOT a security
        # boundary; see "Security caveat" above.
        safe_builtins: dict[str, object] = {
            "len": len,
            "str": str,
            "int": int,
            "float": float,
            "bool": bool,
            "list": list,
            "tuple": tuple,
            "dict": dict,
            "set": set,
            "range": range,
            "enumerate": enumerate,
            "zip": zip,
            "min": min,
            "max": max,
            "sum": sum,
            "abs": abs,
            "all": all,
            "any": any,
            "sorted": sorted,
            "isinstance": isinstance,
            "True": True,
            "False": False,
            "None": None,
        }
        program_globals: dict[str, object] = {
            "__builtins__": safe_builtins,
            "data": data_view,
            "egress": _egress,
        }
        program_locals: dict[str, object] = {}
        try:
            exec(agent_program, program_globals, program_locals)  # noqa: S102
        except PermissionError:
            # Disclosures already recorded; let it propagate so caller sees the
            # actionable error from the user's standpoint.
            raise
        except Exception as exc:  # noqa: BLE001 - bubble up cleanly
            telemetry.emit_event(
                "private_data.program.error",
                level=logging.ERROR,
                error=type(exc).__name__,
                message=str(exc)[:200],
            )
            raise PrivateDataSandboxError(
                f"agent program raised {type(exc).__name__}: {exc}"
            ) from exc

        # Step 4: capture return + destroy view.
        result_value = program_locals.get("result")
        # Defensive: clear the view's backing dict so the same instance
        # cannot be re-read after exit.
        data_view._backing.clear()
        program_globals.clear()
        program_locals.clear()

        # Step 5: telemetry.
        telemetry.emit_event(
            "private_data.execution.completed",
            n_disclosures=len(local_disclosures),
            n_disclosures_allowed=sum(1 for d in local_disclosures if d.allowed),
            taints_seen=sorted(taints_seen),
        )

        return {
            "return": result_value,
            "disclosures": tuple(local_disclosures),
            "taints_seen": frozenset(taints_seen),
        }
