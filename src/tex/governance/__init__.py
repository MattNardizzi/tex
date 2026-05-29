"""
[Architecture: Layer 4 (Execution Governance)] — deeper governance subpackages — path_policy, kernel_mcp, stpa_specs (test-only), private_data_exec/ifc (wired via specialists/ifc_specialist)

See ARCHITECTURE.md for the full six-layer model.

Governance Layer
================

System-level governance over agent execution paths and tool calls.

Modules
-------
  path_policy/      Runtime governance for AI agents: policies on PATHS
                    (not just single tool calls). Strengthens the replay
                    and governance layer.

  kernel_mcp/       Kernel-level / syscall-style governance for MCP tool
                    calls. Treats MCP as privileged-syscall surface.

  private_data_exec/  Sandboxed execution environment that protects user
                      data from compromised models or providers.

  stpa_specs/       System-Theoretic Process Analysis hazard specs and
                    formal data-flow / tool-sequence safety specifications.
                    Strengthens enterprise compliance language.

Priority: P1.

"""

# Architectural layer marker (see ARCHITECTURE.md).
# Queryable as `from tex.governance import __layer__, __layer_kind__`.
__layer__: int | None = 4
__layer_kind__: str = 'execution_governance'

__all__ = []
