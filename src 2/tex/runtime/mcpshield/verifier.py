"""
MCPShield Property Verifier.

Reference: arxiv 2604.05969 (Acharya & Gupta), §IV.

Implements the four fundamental security properties of the MCP transition
system, each with the decidability rationale claimed by the paper:

  Property 1 (Tool Integrity).
      ∀ transitions t with action='tool_invoke' over tool T,
        H(T.definition_at_invocation) = T.approval_hash.
      Decidable in O(|Σ_τ| · |T|) by hashing each invoked tool definition
      and comparing to the registry hash.

  Property 2 (Data Confinement).
      Sensitive data with label ℓ never reaches a server in a trust domain
      that is not authorised for that label. Decidable via the product
      automaton of the LTS and a finite security-level monitor; we
      approximate it by reachability over (state, current_label) pairs.

  Property 3 (Privilege Boundedness).
      For every tool invocation, the agent's effective capabilities are
      a subset of (declared_caps_of_tool ∩ agent_caps_at_state). Defends
      against TC4 privilege escalation.

  Property 4 (Context Isolation).
      Knowledge from one trust domain cannot influence behaviour toward
      another without an explicit cross_domain action with authorized=True
      preceding the cross-domain tool invocation. Defends against TV9
      context bleed and TV19 memory poisoning.

API:

    verify_property(model, property_ltl=...) → (ok, counterexample_path)

For backwards compatibility ``property_ltl`` accepts a property name
(``'tool_integrity'`` etc.) or one of a small set of canonical
LTL-shaped strings the paper uses informally. Unknown identifiers raise
``ValueError`` rather than silently returning False.

Counterexample paths are tuples of human-readable transition descriptions
ending at the first violating step.

Priority: P1.
"""

from __future__ import annotations

from tex.observability.telemetry import emit_event, get_logger
from tex.runtime.mcpshield.lts_model import (
    Capability,
    LtsModel,
    SecurityLabel,
    Transition,
    label_dominates,
)

_logger = get_logger("tex.runtime.mcpshield.verifier")


PROPERTY_ALIASES: dict[str, str] = {
    "tool_integrity": "tool_integrity",
    "G(invoke -> hash_match)": "tool_integrity",
    "data_confinement": "data_confinement",
    "G(secret -> !leak_to_low_domain)": "data_confinement",
    "privilege_boundedness": "privilege_boundedness",
    "G(invoke -> caps_subset)": "privilege_boundedness",
    "context_isolation": "context_isolation",
    "G(cross_domain_use -> authorized)": "context_isolation",
}


def verify_property(
    model: LtsModel,
    *,
    property_ltl: str,
) -> tuple[bool, tuple[str, ...]]:
    """Verify one of MCPShield's four properties on the given model.

    Returns ``(ok, counterexample_path)``. When ``ok`` is True, the
    counterexample is empty.
    """
    key = PROPERTY_ALIASES.get(property_ltl)
    if key is None:
        raise ValueError(
            f"unknown property '{property_ltl}'. Valid: "
            f"{sorted(set(PROPERTY_ALIASES.values()))}"
        )

    if key == "tool_integrity":
        ok, cx = _check_tool_integrity(model)
    elif key == "data_confinement":
        ok, cx = _check_data_confinement(model)
    elif key == "privilege_boundedness":
        ok, cx = _check_privilege_boundedness(model)
    elif key == "context_isolation":
        ok, cx = _check_context_isolation(model)
    else:  # pragma: no cover — already filtered above
        raise ValueError(f"unhandled property: {key}")

    emit_event(
        "mcpshield.verify",
        logger=_logger,
        property=key,
        ok=ok,
        cx_length=len(cx),
        n_states=len(model.states),
        n_transitions=len(model.transitions),
    )
    return ok, cx


# ----------------------------------------------------------------------
# Property 1: Tool Integrity.
# ----------------------------------------------------------------------
def _check_tool_integrity(model: LtsModel) -> tuple[bool, tuple[str, ...]]:
    """Each invocation hashes the tool's definition_blob at runtime and
    asserts equality with the approval-time hash. The LTS payload is
    expected to carry ``runtime_definition_blob``; if absent we fall back
    to the registry's ``definition_blob`` (i.e. the tool was unchanged).
    """
    path: list[str] = []
    for tr in model.transitions:
        path.append(_render(tr))
        if tr.action != "tool_invoke":
            continue
        tool_name = tr.payload.get("tool")
        if tool_name is None:
            return False, tuple(path + ["tool_invoke missing 'tool' name"])
        tdef = model.tool(tool_name)
        if tdef is None:
            return False, tuple(path + [f"tool '{tool_name}' not in registry"])
        runtime_blob = tr.payload.get("runtime_definition_blob", tdef.definition_blob)
        runtime_hash = tdef.hash_definition(runtime_blob)
        if runtime_hash != tdef.approval_hash_hex:
            return False, tuple(
                path + [f"hash mismatch for '{tool_name}': "
                        f"approval={tdef.approval_hash_hex[:12]}…, "
                        f"runtime={runtime_hash[:12]}…"]
            )
    return True, ()


# ----------------------------------------------------------------------
# Property 2: Data Confinement.
# ----------------------------------------------------------------------
def _check_data_confinement(model: LtsModel) -> tuple[bool, tuple[str, ...]]:
    """Reachability over (state, current_max_label) pairs.

    The label monitor tracks the maximum label of any data value that has
    flowed into the agent's working set. When a tool invocation targets a
    server whose trust domain's policy allows at most ``max_allowed_label``,
    a violation occurs if the carried label dominates that allowance.

    The policy → max_allowed_label mapping is encoded in the trust domain's
    ``policy`` field as ``"max_label=<level>"`` (e.g. ``"max_label=internal"``).
    Domains without that prefix are assumed to allow all labels (``secret``).
    """
    path: list[str] = []
    current_label: SecurityLabel = SecurityLabel.PUBLIC

    for tr in model.transitions:
        path.append(_render(tr))

        if tr.action == "data_flow":
            new_label = tr.payload.get("dst_label")
            if isinstance(new_label, SecurityLabel):
                if label_dominates(new_label, current_label):
                    current_label = new_label

        elif tr.action == "tool_invoke":
            tool_name = tr.payload.get("tool")
            if tool_name is None:
                continue
            tdef = model.tool(tool_name)
            if tdef is None:
                return False, tuple(path + [f"tool '{tool_name}' not in registry"])

            # Determine target domain's max allowed label.
            target_domain = model.domain_of_tool(tool_name)
            allowed = _max_allowed_label(target_domain.policy if target_domain else "")

            # Use the carried-label payload if explicit; else current monitor.
            data_in = tr.payload.get("data_in", current_label)
            if isinstance(data_in, SecurityLabel):
                carried = data_in
            else:
                carried = current_label

            if label_dominates(carried, allowed) and carried != allowed:
                return False, tuple(
                    path + [
                        f"data label {carried.value} flows into tool "
                        f"'{tool_name}' in domain '"
                        f"{target_domain.domain_id if target_domain else '<none>'}' "
                        f"allowing only {allowed.value}"
                    ]
                )

    return True, ()


def _max_allowed_label(policy: str) -> SecurityLabel:
    if "max_label=" in policy:
        token = policy.split("max_label=", 1)[1].split()[0].strip(" ;,")
        try:
            return SecurityLabel(token)
        except ValueError:
            return SecurityLabel.SECRET
    return SecurityLabel.SECRET


# ----------------------------------------------------------------------
# Property 3: Privilege Boundedness.
# ----------------------------------------------------------------------
def _check_privilege_boundedness(model: LtsModel) -> tuple[bool, tuple[str, ...]]:
    """Effective capabilities of every tool_invoke must satisfy
    requested ⊆ (tool.declared_perms ∩ agent_caps).
    """
    path: list[str] = []
    for tr in model.transitions:
        path.append(_render(tr))
        if tr.action != "tool_invoke":
            continue

        tool_name = tr.payload.get("tool")
        if tool_name is None:
            continue
        tdef = model.tool(tool_name)
        if tdef is None:
            return False, tuple(path + [f"tool '{tool_name}' not in registry"])

        agent_caps = _coerce_capset(tr.payload.get("agent_caps", set()))
        requested = _coerce_capset(tr.payload.get("requested_caps", {tdef.capability}))

        envelope = tdef.declared_perms & agent_caps
        excess = requested - envelope
        if excess:
            return False, tuple(
                path + [
                    f"tool '{tool_name}' requested caps {sorted(c.value for c in excess)} "
                    f"exceed envelope {sorted(c.value for c in envelope)}"
                ]
            )

    return True, ()


def _coerce_capset(raw) -> frozenset[Capability]:
    if isinstance(raw, frozenset):
        return raw  # type: ignore[return-value]
    if isinstance(raw, (set, list, tuple)):
        out = set()
        for x in raw:
            if isinstance(x, Capability):
                out.add(x)
            else:
                out.add(Capability(x))
        return frozenset(out)
    if isinstance(raw, Capability):
        return frozenset({raw})
    if isinstance(raw, str):
        return frozenset({Capability(raw)})
    return frozenset()


# ----------------------------------------------------------------------
# Property 4: Context Isolation.
# ----------------------------------------------------------------------
def _check_context_isolation(model: LtsModel) -> tuple[bool, tuple[str, ...]]:
    """A tool in domain D_b cannot consume data originating in domain D_a
    unless an authorised cross_domain transition (D_a → D_b) preceded it.

    Track per-pair authorisation set updated on cross_domain transitions
    with ``authorized=True``. On every tool_invoke we look at
    ``data_origin_domain`` in the payload (or fall through). If origin and
    target differ and not authorised, that is a violation.
    """
    authorized_pairs: set[tuple[str, str]] = set()
    path: list[str] = []

    for tr in model.transitions:
        path.append(_render(tr))

        if tr.action == "cross_domain":
            if tr.payload.get("authorized") is True:
                pair = (tr.payload.get("from_domain"), tr.payload.get("to_domain"))
                if pair[0] is not None and pair[1] is not None:
                    authorized_pairs.add(pair)
            continue

        if tr.action != "tool_invoke":
            continue

        tool_name = tr.payload.get("tool")
        target = model.domain_of_tool(tool_name) if tool_name else None
        origin = tr.payload.get("data_origin_domain")
        if target is None or origin is None or origin == target.domain_id:
            continue
        if (origin, target.domain_id) not in authorized_pairs:
            return False, tuple(
                path + [
                    f"unauthorised cross-domain use: data from '{origin}' "
                    f"into tool '{tool_name}' in domain '{target.domain_id}'"
                ]
            )

    return True, ()


# ----------------------------------------------------------------------
def _render(tr: Transition) -> str:
    boundary = ""
    if tr.trust_boundary is not None:
        boundary = (
            f" [{tr.trust_boundary.from_zone}→"
            f"{tr.trust_boundary.to_zone}]"
        )
    return f"{tr.q_from} -[{tr.action}]-> {tr.q_to}{boundary}"
