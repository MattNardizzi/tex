"""
[Architecture: Pending] — parked work — interop stubs for A2A, Okta, Microsoft, NIST, Ping

See ARCHITECTURE.md for the full six-layer model.

_pending — code that is parked, not part of the active product.

Files in this directory:
  - exist but are not imported by anything in src/tex/.
  - may contain NotImplementedError stubs without blocking anything.

The underscore prefix is the signal: "intentionally not wired yet."

When to restore something from here:
  - Move the directory back to src/tex/.
  - Add tests under tests/<package>/.
  - Wire the integration into the appropriate runtime call site.

Current contents:
  - interop/  Microsoft, Okta, Ping, NIST, A2A integration stubs.
              Parked until an integration push lands on the roadmap.

"""

# Architectural layer marker (see ARCHITECTURE.md).
# Queryable as `from tex._pending import __layer__, __layer_kind__`.
__layer__: int | None = None
__layer_kind__: str = 'pending'
