"""
Private-Data Execution Environment.

Reference: Stanley, Verma, Tsai, Kallas, Kumar. "An AI Agent Execution
Environment to Safeguard User Data." arXiv:2604.19657 (Apr 2026).

Sandboxed execution environment that protects user data from compromised
models or providers. The agent reasoning happens in a confidential boundary;
user data never leaves except via explicit, audited capability invocations.

Aligns with the EU AI Act Article 26 deployer obligations and forms the
foundation for the "host-independent verifiability" insurer pitch.

Public API
----------
  PrivateDataSandbox      — the GAAP-style execution environment
  PermissionDatabase      — user permission store (data_name x party -> allow)
  PermissionSpec          — single permission entry
  ToolAnnotation          — per-tool disclosure annotation (GAAP §3.3.5)
  DisclosureRecord        — one entry in the disclosure log
  DisclosureLog           — append-only disclosure history
  PrivateDataSandboxError — sandbox setup / teardown / program failures

Priority: P1.
"""

from tex.governance.private_data_exec.sandbox import (
    DisclosureLog,
    DisclosureRecord,
    PermissionDatabase,
    PermissionSpec,
    PrivateDataSandbox,
    PrivateDataSandboxError,
    ToolAnnotation,
)

__all__ = [
    "DisclosureLog",
    "DisclosureRecord",
    "PermissionDatabase",
    "PermissionSpec",
    "PrivateDataSandbox",
    "PrivateDataSandboxError",
    "ToolAnnotation",
]
