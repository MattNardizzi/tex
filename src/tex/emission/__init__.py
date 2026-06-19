"""
tex.emission — the tool-call emission gate.

A THIRD, EARLIER enforcement point off the same sealed ``CapabilitySurface`` the
discovery filter and capability stream already read (discovery → **emission** →
adjudication). Where adjudication *refuses* an emitted forbidden tool call, this
gate aims to make that call **un-emittable**:

  * ``constraint``        — the pure, sealable ``DecoderConstraint`` builder.
  * ``provider_rewrite``  — Approach B: re-assert the allowlist in a hosted
                            provider's request (``provider-trusted``).
  * ``vllm_mapping``      — Approach A: map the constraint to vLLM guided-decoding
                            params + the fail-closed serving policy (``Tex-enforced``).
  * ``seal``              — commit the constraint digest as a ``SealedFact`` so a
                            verdict can prove "decoded under allowlist H."

Honest floor: covers ONLY the tool-emission actuator, ONLY where Tex owns or can
constrain the decoder, ONLY at name/shape granularity. A permitted tool can still
semantically launder; intent stays the PDP's job. Sound only inside the admission
("born-in-a-box") regime that funnels all actuation through the gated decoder.
"""

from __future__ import annotations

from tex.emission.constraint import DecoderConstraint, compile_constraint
from tex.emission.provider_rewrite import (
    PROVIDER_ANTHROPIC,
    PROVIDER_OPENAI,
    detect_provider,
    rewrite_provider_request,
)
from tex.emission.seal import (
    APPROACH_PROVIDER_TRUSTED,
    APPROACH_TEX_ENFORCED,
    build_constraint_fact,
    seal_constraint,
)
from tex.emission.vllm_mapping import (
    ServingDecision,
    VllmGuidedParams,
    refuse_unconstrained_request,
    to_vllm_guided,
    vllm_serving_policy,
)

__all__ = [
    "DecoderConstraint",
    "compile_constraint",
    "rewrite_provider_request",
    "detect_provider",
    "PROVIDER_OPENAI",
    "PROVIDER_ANTHROPIC",
    "to_vllm_guided",
    "VllmGuidedParams",
    "vllm_serving_policy",
    "ServingDecision",
    "refuse_unconstrained_request",
    "build_constraint_fact",
    "seal_constraint",
    "APPROACH_PROVIDER_TRUSTED",
    "APPROACH_TEX_ENFORCED",
]
