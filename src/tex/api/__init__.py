"""
[Architecture: Cross-cutting (HTTP)] — 22 routers spanning all six layers — ~80 endpoints

See ARCHITECTURE.md for the full six-layer model.
"""

# Architectural layer marker (see ARCHITECTURE.md).
# Queryable as `from tex.api import __layer__, __layer_kind__`.
__layer__: int | None = None
__layer_kind__: str = 'cross_cutting_http'

