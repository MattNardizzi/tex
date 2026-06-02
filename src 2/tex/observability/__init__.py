"""
[Architecture: Layer 3 (Monitoring)] — OpenTelemetry telemetry and discovery metrics

See ARCHITECTURE.md for the full six-layer model.
"""

# Architectural layer marker (see ARCHITECTURE.md).
# Queryable as `from tex.observability import __layer__, __layer_kind__`.
__layer__: int | None = 3
__layer_kind__: str = 'monitoring'

