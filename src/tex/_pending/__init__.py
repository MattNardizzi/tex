"""
[Architecture: Pending] — parked work — interop stubs for A2A, Okta, Microsoft, NIST, Ping

See ARCHITECTURE.md for the full six-layer model.

_pending — code that is parked, not part of the active product.

Files in this directory:
  - exist but are not imported by anything in src/tex/.
  - may contain NotImplementedError stubs without blocking anything.

The underscore prefix is the signal: "intentionally not wired yet."

READ THIS BEFORE QUOTING ANYTHING IN HERE
-----------------------------------------
Nothing in this directory describes the shipping system, and some of it
describes a system that does not exist yet. The modules under ``pitch/`` in
particular are unsent draft collateral, and several state post-quantum
signing (ML-DSA / FIPS 204) as the primary algorithm.

That is NOT what runs. The live signer is ECDSA-P256. ``tex.evidence.seal``
falls back to it whenever no ML-DSA backend is present, logs the downgrade
loudly, and stamps every record with the algorithm that actually produced it
— so a record is always self-describing even where this prose is not. The
repository README's "What we claim — and what we don't yet" section is the
authority on every claim; where this directory disagrees with it, this
directory is wrong.

Treat these files as notes toward a future version, never as a description
of the current one, and never as copy to lift into anything a reader sees.

When to restore something from here:
  - Move the directory back to src/tex/.
  - Add tests under tests/<package>/.
  - Wire the integration into the appropriate runtime call site.
  - Re-check every claim in its prose against what then ships.

Current contents:
  - interop/     Microsoft, Okta, Ping, NIST, A2A integration stubs.
                 Parked until an integration push lands on the roadmap.
  - pitch/       Draft audience-specific collateral. Unsent, unreviewed, and
                 the main source of the overclaiming noted above.
  - api/         Route sketches with no router registration.
  - compliance/  Regime-mapping drafts.
  - events/      Event-shape drafts.
  - graph/       Graph-model drafts.

"""

# Architectural layer marker (see ARCHITECTURE.md).
# Queryable as `from tex._pending import __layer__, __layer_kind__`.
__layer__: int | None = None
__layer_kind__: str = 'pending'
