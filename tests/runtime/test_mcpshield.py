"""
MCPShield tests.

Acceptance criterion: verify_property succeeds on a 10-state model.

Test plan:
  - SecurityLabel lattice ordering correctness
  - Trust domain coverage and lookup
  - ToolDefinition.hash_definition stable + collision-resistant property
    (different inputs → different hashes)
  - 10-state clean model passes all four properties
  - Tool integrity counterexample: runtime hash mismatch
  - Data confinement counterexample: SECRET label flows to PUBLIC-only domain
  - Privilege boundedness counterexample: requested caps exceed envelope
  - Context isolation counterexample: data origin from D_a flows into tool
    in D_b without prior cross_domain authorization
  - Authorised cross_domain transition allows the subsequent invocation
  - PROPERTY_ALIASES mapping covers the LTL-shaped strings the paper uses
  - Unknown property name raises ValueError
"""

from __future__ import annotations

import pytest

from tex.runtime.mcpshield import (
    Capability,
    LtsModel,
    PROPERTY_ALIASES,
    SecurityLabel,
    ToolDefinition,
    Transition,
    TrustBoundary,
    TrustDomain,
    label_dominates,
    verify_property,
)


# ----------------------------------------------------------------------
# Lattice & primitives.
# ----------------------------------------------------------------------
class TestSecurityLabel:
    def test_label_ordering(self) -> None:
        assert label_dominates(SecurityLabel.SECRET, SecurityLabel.PUBLIC)
        assert label_dominates(SecurityLabel.CONFIDENTIAL, SecurityLabel.INTERNAL)
        assert label_dominates(SecurityLabel.SECRET, SecurityLabel.SECRET)
        assert not label_dominates(SecurityLabel.PUBLIC, SecurityLabel.SECRET)


class TestTrustDomain:
    def test_covers_lookup(self) -> None:
        d = TrustDomain(
            domain_id="d1",
            servers=frozenset({"s1"}),
            tools=frozenset({"t1", "t2"}),
            policy="max_label=internal",
        )
        assert d.covers_server("s1")
        assert not d.covers_server("s2")
        assert d.covers_tool("t2")
        assert not d.covers_tool("t3")


class TestToolDefinition:
    def test_hash_stable(self) -> None:
        h1 = ToolDefinition.hash_definition("foo")
        h2 = ToolDefinition.hash_definition("foo")
        assert h1 == h2

    def test_hash_changes_with_input(self) -> None:
        h1 = ToolDefinition.hash_definition("foo")
        h2 = ToolDefinition.hash_definition("foo ")  # trailing space
        assert h1 != h2

    def test_hash_is_sha256_hex(self) -> None:
        h = ToolDefinition.hash_definition("x")
        assert len(h) == 64
        int(h, 16)  # parses as hex


# ----------------------------------------------------------------------
# Property alias coverage.
# ----------------------------------------------------------------------
def test_property_aliases_cover_all_four() -> None:
    assert set(PROPERTY_ALIASES.values()) == {
        "tool_integrity",
        "data_confinement",
        "privilege_boundedness",
        "context_isolation",
    }


def test_unknown_property_raises() -> None:
    m = LtsModel(states=("q0",), transitions=(), trust_boundaries=())
    with pytest.raises(ValueError, match="unknown property"):
        verify_property(m, property_ltl="not_a_real_property")


# ----------------------------------------------------------------------
# 10-state clean model.
# ----------------------------------------------------------------------
def _build_clean_10_state_model() -> LtsModel:
    """Construct a clean 10-state MCP model that satisfies all four
    properties. Exercises tool_invoke, data_flow, and cross_domain."""
    blob_read = "read_file(path: str) -> str"
    blob_send = "send_internal(payload: str) -> bool"
    blob_log = "audit_log(event: str) -> bool"

    read_tool = ToolDefinition(
        name="read_file", server="srv_files", capability=Capability.READ,
        declared_perms=frozenset({Capability.READ}),
        definition_blob=blob_read,
        approval_hash_hex=ToolDefinition.hash_definition(blob_read),
    )
    send_tool = ToolDefinition(
        name="send_internal", server="srv_internal", capability=Capability.NETWORK,
        declared_perms=frozenset({Capability.NETWORK}),
        definition_blob=blob_send,
        approval_hash_hex=ToolDefinition.hash_definition(blob_send),
    )
    log_tool = ToolDefinition(
        name="audit_log", server="srv_audit", capability=Capability.WRITE,
        declared_perms=frozenset({Capability.WRITE}),
        definition_blob=blob_log,
        approval_hash_hex=ToolDefinition.hash_definition(blob_log),
    )

    d_files = TrustDomain(domain_id="files", servers=frozenset({"srv_files"}),
                          tools=frozenset({"read_file"}),
                          policy="max_label=confidential")
    d_internal = TrustDomain(domain_id="internal", servers=frozenset({"srv_internal"}),
                             tools=frozenset({"send_internal"}),
                             policy="max_label=confidential")
    d_audit = TrustDomain(domain_id="audit", servers=frozenset({"srv_audit"}),
                          tools=frozenset({"audit_log"}),
                          policy="max_label=secret")

    states = tuple(f"q{i}" for i in range(10))
    transitions = (
        # q0->q1: authorize files->internal cross-domain so later tool calls are legal.
        Transition(q_from="q0", action="cross_domain", q_to="q1",
                   payload={"from_domain": "files", "to_domain": "internal",
                            "authorized": True}),
        # q1->q2: read a file in domain "files".
        Transition(q_from="q1", action="tool_invoke", q_to="q2",
                   payload={"tool": "read_file", "agent_caps": {"read"},
                            "requested_caps": {"read"},
                            "data_origin_domain": "files",
                            "data_in": SecurityLabel.INTERNAL}),
        # q2->q3: data flow with INTERNAL label.
        Transition(q_from="q2", action="data_flow", q_to="q3",
                   payload={"data": "report", "dst_label": SecurityLabel.INTERNAL}),
        # q3->q4: send_internal in domain "internal" — origin "files",
        # already authorised at q0->q1.
        Transition(q_from="q3", action="tool_invoke", q_to="q4",
                   payload={"tool": "send_internal", "agent_caps": {"network"},
                            "requested_caps": {"network"},
                            "data_origin_domain": "files",
                            "data_in": SecurityLabel.INTERNAL}),
        # q4->q5: audit log entry. Authorise the cross-domain step first.
        Transition(q_from="q4", action="cross_domain", q_to="q5",
                   payload={"from_domain": "internal", "to_domain": "audit",
                            "authorized": True}),
        # q5->q6: log
        Transition(q_from="q5", action="tool_invoke", q_to="q6",
                   payload={"tool": "audit_log", "agent_caps": {"write"},
                            "requested_caps": {"write"},
                            "data_origin_domain": "internal",
                            "data_in": SecurityLabel.INTERNAL}),
        # q6->q7: another data_flow inside same domain (no cross-boundary)
        Transition(q_from="q6", action="data_flow", q_to="q7",
                   payload={"data": "ack", "dst_label": SecurityLabel.PUBLIC}),
        # q7->q8: another read_file (re-use after authorised cross-domain).
        Transition(q_from="q7", action="tool_invoke", q_to="q8",
                   payload={"tool": "read_file", "agent_caps": {"read"},
                            "requested_caps": {"read"},
                            "data_origin_domain": "files",
                            "data_in": SecurityLabel.PUBLIC}),
        # q8->q9: clean termination.
        Transition(q_from="q8", action="data_flow", q_to="q9",
                   payload={"data": "done", "dst_label": SecurityLabel.PUBLIC}),
    )

    return LtsModel(
        states=states,
        transitions=transitions,
        trust_boundaries=(),
        initial_state="q0",
        agents=("agent_main",),
        servers=("srv_files", "srv_internal", "srv_audit"),
        tools=(read_tool, send_tool, log_tool),
        domains=(d_files, d_internal, d_audit),
    )


class TestTenStateClean:
    def test_clean_model_has_ten_states(self) -> None:
        m = _build_clean_10_state_model()
        assert len(m.states) == 10

    def test_tool_integrity_passes(self) -> None:
        m = _build_clean_10_state_model()
        ok, cx = verify_property(m, property_ltl="tool_integrity")
        assert ok, cx

    def test_data_confinement_passes(self) -> None:
        m = _build_clean_10_state_model()
        ok, cx = verify_property(m, property_ltl="data_confinement")
        assert ok, cx

    def test_privilege_boundedness_passes(self) -> None:
        m = _build_clean_10_state_model()
        ok, cx = verify_property(m, property_ltl="privilege_boundedness")
        assert ok, cx

    def test_context_isolation_passes(self) -> None:
        m = _build_clean_10_state_model()
        ok, cx = verify_property(m, property_ltl="context_isolation")
        assert ok, cx

    def test_ltl_shaped_aliases_resolve(self) -> None:
        m = _build_clean_10_state_model()
        ok, _ = verify_property(m, property_ltl="G(invoke -> hash_match)")
        assert ok


# ----------------------------------------------------------------------
# Counterexamples — each property's failure mode.
# ----------------------------------------------------------------------
class TestCounterexamples:
    def test_tool_integrity_hash_mismatch(self) -> None:
        blob = "read_file(path: str) -> str"
        tool = ToolDefinition(
            name="read_file", server="s", capability=Capability.READ,
            declared_perms=frozenset({Capability.READ}),
            definition_blob=blob,
            approval_hash_hex=ToolDefinition.hash_definition(blob),
        )
        d = TrustDomain(domain_id="d", servers=frozenset({"s"}),
                        tools=frozenset({"read_file"}), policy="")
        # Runtime blob differs (server-side definition was swapped).
        trs = (
            Transition(q_from="q0", action="tool_invoke", q_to="q1",
                       payload={"tool": "read_file",
                                "runtime_definition_blob": "read_file_PWNED(p: str) -> str",
                                "agent_caps": {"read"}}),
        )
        m = LtsModel(states=("q0", "q1"), transitions=trs, trust_boundaries=(),
                     tools=(tool,), domains=(d,))
        ok, cx = verify_property(m, property_ltl="tool_integrity")
        assert not ok
        assert any("hash mismatch" in line for line in cx)

    def test_tool_integrity_unknown_tool(self) -> None:
        trs = (
            Transition(q_from="q0", action="tool_invoke", q_to="q1",
                       payload={"tool": "ghost"}),
        )
        m = LtsModel(states=("q0", "q1"), transitions=trs, trust_boundaries=())
        ok, cx = verify_property(m, property_ltl="tool_integrity")
        assert not ok
        assert any("not in registry" in line for line in cx)

    def test_data_confinement_secret_to_public(self) -> None:
        blob = "send_http(url: str, body: str) -> int"
        tool = ToolDefinition(
            name="send_http", server="s", capability=Capability.NETWORK,
            declared_perms=frozenset({Capability.NETWORK}),
            definition_blob=blob,
            approval_hash_hex=ToolDefinition.hash_definition(blob),
        )
        d_pub = TrustDomain(domain_id="pub", servers=frozenset({"s"}),
                            tools=frozenset({"send_http"}),
                            policy="max_label=public")
        trs = (
            Transition(q_from="q0", action="data_flow", q_to="q1",
                       payload={"data": "key", "dst_label": SecurityLabel.SECRET}),
            Transition(q_from="q1", action="tool_invoke", q_to="q2",
                       payload={"tool": "send_http", "agent_caps": {"network"}}),
        )
        m = LtsModel(states=("q0", "q1", "q2"), transitions=trs,
                     trust_boundaries=(), tools=(tool,), domains=(d_pub,))
        ok, cx = verify_property(m, property_ltl="data_confinement")
        assert not ok
        assert any("secret" in line.lower() for line in cx)

    def test_privilege_boundedness_excess_caps(self) -> None:
        blob = "read_file(path: str) -> str"
        tool = ToolDefinition(
            name="read_file", server="s", capability=Capability.READ,
            declared_perms=frozenset({Capability.READ}),  # only READ allowed
            definition_blob=blob,
            approval_hash_hex=ToolDefinition.hash_definition(blob),
        )
        d = TrustDomain(domain_id="d", servers=frozenset({"s"}),
                        tools=frozenset({"read_file"}), policy="")
        trs = (
            Transition(q_from="q0", action="tool_invoke", q_to="q1",
                       payload={"tool": "read_file",
                                "agent_caps": {"read", "exec"},
                                "requested_caps": {"exec"}}),  # asks for EXEC
        )
        m = LtsModel(states=("q0", "q1"), transitions=trs, trust_boundaries=(),
                     tools=(tool,), domains=(d,))
        ok, cx = verify_property(m, property_ltl="privilege_boundedness")
        assert not ok
        assert any("exceed" in line for line in cx)

    def test_privilege_boundedness_unknown_tool(self) -> None:
        trs = (
            Transition(q_from="q0", action="tool_invoke", q_to="q1",
                       payload={"tool": "ghost",
                                "agent_caps": {"read"}, "requested_caps": {"read"}}),
        )
        m = LtsModel(states=("q0", "q1"), transitions=trs, trust_boundaries=())
        ok, cx = verify_property(m, property_ltl="privilege_boundedness")
        assert not ok
        assert any("not in registry" in line for line in cx)

    def test_context_isolation_unauthorised_cross_domain(self) -> None:
        blob = "send(url: str) -> int"
        tool = ToolDefinition(
            name="send", server="s_pub", capability=Capability.NETWORK,
            declared_perms=frozenset({Capability.NETWORK}),
            definition_blob=blob,
            approval_hash_hex=ToolDefinition.hash_definition(blob),
        )
        d_a = TrustDomain(domain_id="A", servers=frozenset({"s_a"}),
                          tools=frozenset({"read_a"}), policy="")
        d_b = TrustDomain(domain_id="B", servers=frozenset({"s_pub"}),
                          tools=frozenset({"send"}), policy="")
        trs = (
            # tool_invoke uses data originating in A, but no prior authorised
            # cross_domain A->B transition.
            Transition(q_from="q0", action="tool_invoke", q_to="q1",
                       payload={"tool": "send", "agent_caps": {"network"},
                                "data_origin_domain": "A"}),
        )
        m = LtsModel(states=("q0", "q1"), transitions=trs, trust_boundaries=(),
                     tools=(tool,), domains=(d_a, d_b))
        ok, cx = verify_property(m, property_ltl="context_isolation")
        assert not ok
        assert any("unauthorised cross-domain" in line for line in cx)

    def test_context_isolation_authorised_cross_domain_passes(self) -> None:
        blob = "send(url: str) -> int"
        tool = ToolDefinition(
            name="send", server="s_pub", capability=Capability.NETWORK,
            declared_perms=frozenset({Capability.NETWORK}),
            definition_blob=blob,
            approval_hash_hex=ToolDefinition.hash_definition(blob),
        )
        d_a = TrustDomain(domain_id="A", servers=frozenset({"s_a"}),
                          tools=frozenset({"read_a"}), policy="")
        d_b = TrustDomain(domain_id="B", servers=frozenset({"s_pub"}),
                          tools=frozenset({"send"}), policy="")
        trs = (
            Transition(q_from="q0", action="cross_domain", q_to="q1",
                       payload={"from_domain": "A", "to_domain": "B",
                                "authorized": True}),
            Transition(q_from="q1", action="tool_invoke", q_to="q2",
                       payload={"tool": "send", "agent_caps": {"network"},
                                "data_origin_domain": "A"}),
        )
        m = LtsModel(states=("q0", "q1", "q2"), transitions=trs,
                     trust_boundaries=(), tools=(tool,), domains=(d_a, d_b))
        ok, _ = verify_property(m, property_ltl="context_isolation")
        assert ok

    def test_context_isolation_same_domain_no_violation(self) -> None:
        blob = "read_a(path: str) -> str"
        tool = ToolDefinition(
            name="read_a", server="s_a", capability=Capability.READ,
            declared_perms=frozenset({Capability.READ}),
            definition_blob=blob,
            approval_hash_hex=ToolDefinition.hash_definition(blob),
        )
        d_a = TrustDomain(domain_id="A", servers=frozenset({"s_a"}),
                          tools=frozenset({"read_a"}), policy="")
        trs = (
            Transition(q_from="q0", action="tool_invoke", q_to="q1",
                       payload={"tool": "read_a", "agent_caps": {"read"},
                                "data_origin_domain": "A"}),
        )
        m = LtsModel(states=("q0", "q1"), transitions=trs, trust_boundaries=(),
                     tools=(tool,), domains=(d_a,))
        ok, _ = verify_property(m, property_ltl="context_isolation")
        assert ok

    def test_max_allowed_label_unknown_token_defaults_secret(self) -> None:
        """Domain policy with unknown label token defaults to SECRET (most
        permissive — doesn't raise on parse error)."""
        blob = "t() -> int"
        tool = ToolDefinition(
            name="t", server="s", capability=Capability.READ,
            declared_perms=frozenset({Capability.READ}),
            definition_blob=blob,
            approval_hash_hex=ToolDefinition.hash_definition(blob),
        )
        d = TrustDomain(domain_id="d", servers=frozenset({"s"}),
                        tools=frozenset({"t"}), policy="max_label=garbage")
        trs = (
            Transition(q_from="q0", action="data_flow", q_to="q1",
                       payload={"dst_label": SecurityLabel.SECRET}),
            Transition(q_from="q1", action="tool_invoke", q_to="q2",
                       payload={"tool": "t", "agent_caps": {"read"},
                                "requested_caps": {"read"}}),
        )
        m = LtsModel(states=("q0", "q1", "q2"), transitions=trs,
                     trust_boundaries=(), tools=(tool,), domains=(d,))
        ok, _ = verify_property(m, property_ltl="data_confinement")
        assert ok


# ----------------------------------------------------------------------
# Trust boundary rendering in counterexample output.
# ----------------------------------------------------------------------
def test_trust_boundary_rendered_in_counterexample() -> None:
    blob = "send(url: str) -> int"
    tool = ToolDefinition(
        name="send", server="s_pub", capability=Capability.NETWORK,
        declared_perms=frozenset({Capability.NETWORK}),
        definition_blob=blob,
        approval_hash_hex=ToolDefinition.hash_definition(blob),
    )
    d_b = TrustDomain(domain_id="B", servers=frozenset({"s_pub"}),
                      tools=frozenset({"send"}), policy="max_label=public")
    tb = TrustBoundary(from_zone="agent", to_zone="external_api",
                       label="exfil candidate")
    trs = (
        Transition(q_from="q0", action="data_flow", q_to="q1",
                   payload={"dst_label": SecurityLabel.SECRET}),
        Transition(q_from="q1", action="tool_invoke", q_to="q2",
                   payload={"tool": "send", "agent_caps": {"network"}},
                   trust_boundary=tb),
    )
    m = LtsModel(states=("q0", "q1", "q2"), transitions=trs,
                 trust_boundaries=(tb,), tools=(tool,), domains=(d_b,))
    ok, cx = verify_property(m, property_ltl="data_confinement")
    assert not ok
    assert any("agent→external_api" in line for line in cx)
