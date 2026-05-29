"""
[Architecture: Layer 5 (Evidence)] — regulatory evidence emitters — EU AI Act, FTC, California, Colorado, NY (tested, not invoked at runtime)

See ARCHITECTURE.md for the full six-layer model.

Compliance Layer
================

Regulatory anchor bindings. Each module emits the compliance evidence
artifact a regulator would request, derived from the underlying Tex
evidence chain.

Modules
-------
  eu_ai_act/   Articles 17, 26, 50
  ftc/         FTC §5 (15 U.S.C. § 45) AI substantiation packets
  state/       California SB 942, Colorado AI Act, NY AI Disclosure
  nist/        NIST AI RMF + AI Agent Standards Initiative
  naic/        NAIC Model Bulletin + Cyber Insurance AI Rider

Priority
--------
P0: eu_ai_act/article_50, state/california_sb942, ftc/policy_statement
P1: everything else

"""

# Architectural layer marker (see ARCHITECTURE.md).
# Queryable as `from tex.compliance import __layer__, __layer_kind__`.
__layer__: int | None = 5
__layer_kind__: str = 'evidence'

__all__ = []
