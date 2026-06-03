"""
tex.pep — Policy Enforcement Points.

The PDP (StandingGovernance, /v1/govern) decides. A PEP is the thing in the
path that *asks* and obeys. This package ships the userspace data-plane PEP —
a transparent enforcement proxy that the eBPF kernel-floor redirects into, and
that also runs standalone as an MCP/HTTP sidecar gateway.

The kernel-floor PEP itself (eBPF program + loader) lives outside the Python
package, under ``pep/kernel`` at the repo root, because it is compiled against
the target kernel at deploy time. Both PEPs speak the same fixed contract:
call the PDP, obey ``released``.
"""

__all__ = []
