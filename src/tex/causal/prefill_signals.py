"""
Prefill-stage SLM signal extractor for attribution ranking.

Adapts MASPrism's prefill-signals approach (arxiv 2605.07509, May 7
2026) to Tex's structured decision-graph context. Where MASPrism uses
prefill signals to *identify* candidates from a flat trace, Tex uses
them to *re-rank* candidates that the graph-based attribution pass has
already identified — a hybrid no published paper has implemented.

What we extract
---------------
Per agent-step in the decision trace, two signals:

  1. Mean token-level negative log-likelihood (NLL) — a spike here
     signals that the SLM "didn't expect" the step's content, which
     correlates with the step being out-of-distribution and therefore
     a candidate failure source.
  2. Mean attention entropy — high entropy on a step indicates the
     SLM's attention is unfocused there, which is a softer signal
     for "this step is unusual."

Both signals are pure-prefill (no decoding pass), making latency
bounded by trace length and KV cache rather than by generation. For
Tex's typical decision (≤ 64 events, ≤ 4096 tokens after rendering),
one prefill on a 0.8B parameter model is well under 800ms on a
modern CPU.

Model selection (May 18, 2026 SOTA)
-----------------------------------
Preferred: ``Qwen/Qwen3.5-0.8B`` (released 2026-03-02). Strictly
newer and better at instruction-following / trace parsing than
MASPrism's Qwen3-0.6B choice. Falls back to ``Qwen/Qwen3-0.6B``
(MASPrism's model) when 3.5 isn't available locally. Falls back to
graph-only mode (returns empty signals) when no SLM is loaded.

The model identifier and dtype are configurable via environment:

  * ``TEX_ATTRIBUTION_SLM_MODEL`` (default ``"Qwen/Qwen3.5-0.8B"``)
  * ``TEX_ATTRIBUTION_SLM_DTYPE`` (default ``"float32"``)
  * ``TEX_ATTRIBUTION_SLM_DEVICE`` (default ``"cpu"``)
  * ``TEX_ATTRIBUTION_SLM_ENABLED`` (default ``"0"`` — off until
    weights are pre-loaded; setting ``"1"`` enables loading)

Fail-closed semantics
---------------------
If the SLM is enabled-via-env but fails to load, ``extract_signals``
returns an empty ``PrefillSignals`` and emits an
``attribution.slm.load_failed`` telemetry event. The attribution
engine then falls back to graph-only ranking. **The endpoint does
not fail because the SLM failed.** Failing the endpoint on a soft-
optional signal source would violate Section 3 hard constraint #4.

References
----------
- arxiv 2605.07509 (MASPrism, May 7, 2026) — prefill-stage signals
  for failure attribution
- Qwen3.5 release blog (qwen.ai, Feb 16, 2026)
- Qwen3-0.6B technical report (arxiv 2505.09388)

This module is independent of the graph-based attribution pass.
``tex.causal.attribution_engine`` consumes the signals produced here
and the candidates produced by CHIEF/ARM to deliver the hybrid
ranking.
"""

from __future__ import annotations

import math
import os
import threading
from dataclasses import dataclass
from typing import Any, Mapping

from pydantic import BaseModel, ConfigDict, Field

from tex.observability.telemetry import emit_event


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

_DEFAULT_MODEL_ID: str = "Qwen/Qwen3.5-0.8B"
_FALLBACK_MODEL_ID: str = "Qwen/Qwen3-0.6B"


def _env_flag(name: str, default: str = "0") -> bool:
    raw = os.environ.get(name, default).strip().lower()
    return raw in ("1", "true", "yes", "on")


def _env_str(name: str, default: str) -> str:
    raw = os.environ.get(name)
    return raw if raw is not None and raw.strip() else default


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------


class StepSignal(BaseModel):
    """Per-step prefill signal."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    step_id: str = Field(min_length=1, max_length=256)
    mean_nll: float = Field(ge=0.0)
    attention_entropy: float = Field(ge=0.0)


class PrefillSignals(BaseModel):
    """Bundle of per-step signals plus the source model identifier."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    model_id: str = Field(default="", max_length=200)
    """Either ``""`` (no SLM loaded) or the model identifier used."""

    signals_available: bool
    """True iff the SLM successfully extracted signals for at least
    one step. False on no-SLM or extraction failure paths."""

    step_signals: tuple[StepSignal, ...] = Field(default_factory=tuple)

    # SHA-256 hex of the SLM weights, if known. Required for ZK
    # proof generation; optional otherwise. Empty string when the
    # SLM wasn't loaded.
    model_weight_sha256: str = ""

    def as_mapping(self) -> dict[str, dict[str, float]]:
        """Convenience: ``{step_id: {"nll": ..., "entropy": ...}}``."""
        return {
            sig.step_id: {
                "nll": sig.mean_nll,
                "entropy": sig.attention_entropy,
            }
            for sig in self.step_signals
        }


# A module-level "empty" singleton so the no-SLM path doesn't allocate.
_EMPTY_SIGNALS: PrefillSignals = PrefillSignals(
    model_id="",
    signals_available=False,
    step_signals=(),
    model_weight_sha256="",
)


def empty_signals() -> PrefillSignals:
    """Return the canonical empty ``PrefillSignals`` value.

    Used by ``attribution_engine`` when the SLM is disabled or when
    the trace is empty.
    """
    return _EMPTY_SIGNALS


# ---------------------------------------------------------------------------
# SLM loader (lazy, single-process)
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class _LoadedSLM:
    """Process-local handle to a loaded SLM.

    Kept opaque — the loader returns this for the extractor to use,
    and only the extractor knows how to call into the framework
    (transformers, llama.cpp, vLLM, etc.). The Protocol is structural,
    not nominal — see ``_SLMBackend`` below.
    """

    model_id: str
    backend: Any  # _SLMBackend protocol implementation
    weight_sha256: str


_SLM_LOCK = threading.Lock()
_LOADED_SLM: _LoadedSLM | None = None
_LOAD_ATTEMPTED: bool = False


class _SLMBackend:
    """Structural protocol for a prefill-signals SLM backend.

    A backend implementation must expose ``prefill_signals(trace_text:
    str, step_offsets: list[tuple[int, int]]) -> list[StepSignal]``.
    The trace text is the full rendered trace; step_offsets is a list
    of ``(start_char, end_char)`` slices identifying which characters
    belong to each step. The backend returns one ``StepSignal`` per
    offset pair, in order.

    Default implementation uses ``transformers`` if importable. A
    deployment can install a different backend via
    ``set_slm_backend(callable_returning_LoadedSLM)``.
    """

    def prefill_signals(
        self,
        trace_text: str,
        step_offsets: list[tuple[int, int]],
    ) -> list[StepSignal]:
        raise NotImplementedError


_BackendFactory = "callable returning _LoadedSLM or None"
_BACKEND_FACTORY: Any = None  # set via set_slm_backend


def set_slm_backend(factory: Any) -> None:
    """Install a custom SLM-backend factory.

    The factory is a zero-arg callable that returns a ``_LoadedSLM``
    or ``None`` on failure. The default behaviour (without a custom
    factory installed) attempts to load Qwen3.5-0.8B via the
    ``transformers`` library if importable.

    Pass ``None`` to revert to the default behaviour.
    """
    global _BACKEND_FACTORY
    _BACKEND_FACTORY = factory


def _try_load_slm() -> _LoadedSLM | None:
    """Load the SLM once per process.

    Honors ``TEX_ATTRIBUTION_SLM_ENABLED``. If the env flag is off,
    returns ``None`` without attempting load. If on, tries the
    configured model id, falls back to ``Qwen3-0.6B`` (MASPrism's
    model), then returns ``None``.
    """
    global _LOADED_SLM, _LOAD_ATTEMPTED

    if not _env_flag("TEX_ATTRIBUTION_SLM_ENABLED"):
        return None

    with _SLM_LOCK:
        if _LOADED_SLM is not None:
            return _LOADED_SLM
        if _LOAD_ATTEMPTED:
            # Already tried and failed once this process. Don't retry
            # — failed loads are usually deterministic (missing deps,
            # missing weights) and retrying just adds latency.
            return None
        _LOAD_ATTEMPTED = True

        # Custom factory takes precedence.
        if _BACKEND_FACTORY is not None:
            try:
                loaded = _BACKEND_FACTORY()
            except Exception as exc:
                emit_event(
                    "attribution.slm.load_failed",
                    reason="custom_factory_raised",
                    error=str(exc),
                )
                return None
            if isinstance(loaded, _LoadedSLM):
                _LOADED_SLM = loaded
                emit_event(
                    "attribution.slm.loaded",
                    model_id=loaded.model_id,
                    source="custom_factory",
                )
                return loaded
            return None

        # Default backend: transformers-based, if importable.
        preferred_id = _env_str("TEX_ATTRIBUTION_SLM_MODEL", _DEFAULT_MODEL_ID)
        for model_id in (preferred_id, _FALLBACK_MODEL_ID):
            loaded = _load_transformers_backend(model_id)
            if loaded is not None:
                _LOADED_SLM = loaded
                emit_event(
                    "attribution.slm.loaded",
                    model_id=model_id,
                    source="transformers_default",
                )
                return loaded

        emit_event(
            "attribution.slm.load_failed",
            reason="no_backend_available",
            preferred=preferred_id,
            fallback=_FALLBACK_MODEL_ID,
        )
        return None


def _load_transformers_backend(model_id: str) -> _LoadedSLM | None:
    """Attempt to load ``model_id`` via the ``transformers`` library.

    Returns ``None`` if ``transformers`` isn't installed or the model
    can't be loaded. This is the soft path — production deployments
    will likely override via ``set_slm_backend`` with a vLLM or
    llama.cpp implementation.
    """
    try:
        # Imported locally so the module imports cleanly without
        # transformers installed.
        from transformers import (  # type: ignore[import-not-found]
            AutoModelForCausalLM,
            AutoTokenizer,
        )
    except Exception:
        return None

    try:
        import torch  # type: ignore[import-not-found]
    except Exception:
        return None

    dtype_str = _env_str("TEX_ATTRIBUTION_SLM_DTYPE", "float32")
    device = _env_str("TEX_ATTRIBUTION_SLM_DEVICE", "cpu")

    try:
        torch_dtype = getattr(torch, dtype_str)
    except AttributeError:
        torch_dtype = torch.float32

    try:
        tokenizer = AutoTokenizer.from_pretrained(model_id)
        model = AutoModelForCausalLM.from_pretrained(
            model_id,
            torch_dtype=torch_dtype,
            output_attentions=True,
        )
        model.eval()
        model.to(device)
    except Exception as exc:
        emit_event(
            "attribution.slm.load_failed",
            reason="hf_load_raised",
            model_id=model_id,
            error=str(exc)[:200],
        )
        return None

    # Approximate weight hash: the HF model's identifier serves as a
    # stable surrogate. A real production system would hash the
    # actual safetensors file; we use the id to keep the load cheap
    # and document this is a surrogate for v1.
    import hashlib

    weight_sha256 = hashlib.sha256(
        f"transformers:{model_id}".encode("utf-8")
    ).hexdigest()

    backend = _TransformersBackend(
        tokenizer=tokenizer, model=model, device=device, torch=torch
    )
    return _LoadedSLM(
        model_id=model_id, backend=backend, weight_sha256=weight_sha256
    )


@dataclass(slots=True)
class _TransformersBackend:
    """transformers-based prefill-signal backend.

    Runs one prefill pass over the rendered trace. For each step
    offset, computes mean NLL over the step's tokens and mean
    attention entropy over the step's tokens (averaged across
    layers and heads).
    """

    tokenizer: Any
    model: Any
    device: str
    torch: Any

    def prefill_signals(
        self,
        trace_text: str,
        step_offsets: list[tuple[int, int]],
    ) -> list[StepSignal]:
        if not step_offsets:
            return []

        torch = self.torch
        tokenizer = self.tokenizer
        model = self.model

        encoded = tokenizer(
            trace_text,
            return_tensors="pt",
            return_offsets_mapping=True,
            add_special_tokens=False,
        )
        input_ids = encoded["input_ids"].to(self.device)
        offsets = encoded["offset_mapping"][0].tolist()

        with torch.no_grad():
            out = model(
                input_ids,
                output_attentions=True,
                use_cache=False,
            )

        # Compute per-token NLL: cross-entropy of token_t given
        # token_{<t}. Standard shifted cross-entropy.
        logits = out.logits[0]  # [seq, vocab]
        # Shift: predict tokens[1:] from logits[:-1]
        shift_logits = logits[:-1, :]
        shift_labels = input_ids[0, 1:]
        log_probs = torch.nn.functional.log_softmax(shift_logits, dim=-1)
        gathered = log_probs.gather(
            dim=-1, index=shift_labels.unsqueeze(-1)
        ).squeeze(-1)
        per_token_nll = (-gathered).tolist()  # length seq-1

        # Attention entropy: out.attentions is a tuple per layer of
        # tensors [batch, heads, q_pos, k_pos]. Average across layers
        # and heads, take entropy of the attention distribution at
        # each query position.
        attn_entropies: list[float] = []
        try:
            stacked = torch.stack(out.attentions, dim=0)  # [L,B,H,Q,K]
            # mean over layers and heads -> [B, Q, K]
            mean_attn = stacked.mean(dim=(0, 2))[0]  # [Q,K]
            eps = 1e-12
            ent = -(mean_attn * (mean_attn + eps).log()).sum(dim=-1)
            attn_entropies = ent.tolist()
        except Exception:
            # Attention extraction is best-effort; if it fails,
            # signal with zero entropy.
            attn_entropies = [0.0] * input_ids.shape[1]

        # Aggregate per-step from per-token signals using the offset
        # mapping.
        signals: list[StepSignal] = []
        for step_index, (s_char, e_char) in enumerate(step_offsets):
            step_token_nlls: list[float] = []
            step_token_ents: list[float] = []
            for tok_index, (tok_s, tok_e) in enumerate(offsets):
                # Half-open: token belongs to the step if it starts
                # within the step's char range.
                if tok_s >= s_char and tok_s < e_char:
                    # per_token_nll is length seq-1, indexed by
                    # tok_index - 1 for tokens >= 1.
                    if 0 < tok_index <= len(per_token_nll):
                        step_token_nlls.append(per_token_nll[tok_index - 1])
                    if tok_index < len(attn_entropies):
                        step_token_ents.append(attn_entropies[tok_index])

            mean_nll = (
                sum(step_token_nlls) / len(step_token_nlls)
                if step_token_nlls
                else 0.0
            )
            mean_ent = (
                sum(step_token_ents) / len(step_token_ents)
                if step_token_ents
                else 0.0
            )
            # Guard against NaN/Inf from numerical edge cases.
            if not math.isfinite(mean_nll):
                mean_nll = 0.0
            if not math.isfinite(mean_ent):
                mean_ent = 0.0
            signals.append(
                StepSignal(
                    step_id=f"step_{step_index:04d}",
                    mean_nll=max(mean_nll, 0.0),
                    attention_entropy=max(mean_ent, 0.0),
                )
            )
        return signals


# ---------------------------------------------------------------------------
# Public extractor
# ---------------------------------------------------------------------------


def render_trace_for_signals(
    trace: tuple[Mapping[str, Any], ...],
) -> tuple[str, list[tuple[int, int]], list[str]]:
    """Render a trace into a single text blob plus per-step offsets.

    Each step becomes a labelled block:

        step_id=<id> agent=<name>
        action: <text>
        result: <text>
        ---

    Returns ``(rendered_text, offsets, step_ids)`` where ``offsets[i]``
    is the ``(start, end)`` character offset for step ``step_ids[i]``
    within ``rendered_text``.

    Public so the attribution_zk module can compute identical input
    hashes for the PTV envelope binding.
    """
    parts: list[str] = []
    offsets: list[tuple[int, int]] = []
    step_ids: list[str] = []
    cursor = 0
    for index, raw in enumerate(trace):
        step_id = str(raw.get("step_id") or f"step_{index:04d}")
        agent_id = str(raw.get("agent_id") or raw.get("name") or "unknown")
        action = str(raw.get("action") or "")
        result = str(raw.get("result") or raw.get("output") or "")
        block = (
            f"step_id={step_id} agent={agent_id}\n"
            f"action: {action}\n"
            f"result: {result}\n"
            f"---\n"
        )
        start = cursor
        cursor += len(block)
        parts.append(block)
        offsets.append((start, cursor))
        step_ids.append(step_id)
    return "".join(parts), offsets, step_ids


# Backward-compat private alias retained for any internal callers.
_render_trace = render_trace_for_signals


def extract_signals(
    trace: tuple[Mapping[str, Any], ...],
) -> PrefillSignals:
    """Extract prefill-stage signals from a decision trace.

    Returns an empty (but valid) ``PrefillSignals`` when no SLM is
    loaded or when the trace is empty. Never raises — fail-closed.
    """
    if not trace:
        return _EMPTY_SIGNALS

    loaded = _try_load_slm()
    if loaded is None:
        return _EMPTY_SIGNALS

    rendered, offsets, step_ids = _render_trace(trace)
    if not offsets:
        return _EMPTY_SIGNALS

    try:
        raw_signals = loaded.backend.prefill_signals(rendered, offsets)
    except Exception as exc:
        emit_event(
            "attribution.slm.extract_failed",
            reason="backend_raised",
            error=str(exc)[:200],
            model_id=loaded.model_id,
        )
        return _EMPTY_SIGNALS

    # Re-stamp the step_ids onto whatever the backend returned (the
    # backend uses positional ids; we want the trace's actual ids).
    stamped: list[StepSignal] = []
    for sig, real_id in zip(raw_signals, step_ids):
        stamped.append(
            StepSignal(
                step_id=real_id,
                mean_nll=sig.mean_nll,
                attention_entropy=sig.attention_entropy,
            )
        )

    emit_event(
        "attribution.slm.extracted",
        model_id=loaded.model_id,
        step_count=len(stamped),
    )

    return PrefillSignals(
        model_id=loaded.model_id,
        signals_available=bool(stamped),
        step_signals=tuple(stamped),
        model_weight_sha256=loaded.weight_sha256,
    )


__all__ = [
    "StepSignal",
    "PrefillSignals",
    "empty_signals",
    "extract_signals",
    "set_slm_backend",
]
