"""
[Architecture: Cross-cutting (Voice cognition)] — the grounded spoken-answer cascade.

This package is the integrity boundary of the voice loop. A spoken question
becomes a transcript (self-hosted STT, ``tex.gateway``), the transcript is
answered HERE *only* from sealed facts, and the answer is synthesized back as
speech. There is no free-running model in the speaking seat — the load-bearing
verbalization is ``template.format(**sealed_slots)`` over values that each
trace to a hash, and an always-on exact-match gate re-derives every emitted
handle from the sealed field before Tex is allowed to say it.

The pieces, in dependency order:

  * ``intent``       — deterministic routing: a transcript → a sealed-fact
                       source (one of the six vigil dimensions) or a record
                       handle (a sha256 / decision id), or ABSTAIN.
  * ``answer_forms`` — authored answer templates, one per dimension + the
                       record kind, filled ONLY from sealed slots via the
                       vigil IRON RULE (``vigil.utterances.fill``).
  * ``voice_gate``   — the faithfulness gate: prove the answer is exactly an
                       authored template filled with sealed values; a handle
                       the transcript asserted that contradicts the sealed
                       fact is a structural FORBID; anything unprovable
                       resolves to ABSTAIN. One-sided: it can only ever make a
                       verdict more cautious (PERMIT → ABSTAIN → FORBID).
  * ``voice_ask``    — the ``/v1/ask`` pipeline that wires the above together.
  * ``attestation``  — seals each spoken answer as a hash-chained,
                       ECDSA-P256-signed voice-attestation record (the
                       *chain* proves integrity/ordering; the *signature*
                       proves authorship of one spoken act — named distinctly,
                       never collapsed).

Maturity: the deterministic path is ``production``-shaped and runs today. The
optional neural entailment scorer (``voice_gate.NeuralNLIScorer``) is a
labelled-OFF seam — it does not run in this environment and fails closed to
ABSTAIN (see its docstring). The attestation signs with ECDSA-P256 today, not a
post-quantum algorithm.
"""

from __future__ import annotations

__all__: list[str] = []
