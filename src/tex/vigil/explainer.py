"""
[Architecture: Cross-cutting (Vigil cognition)] — the explanation layer.

The vigil's voice is deterministic and sealed: surprise selects which sealed
truths to speak, authored forms fill from hashed data, every word traces to
proof (see vigil/selector.py and vigil/utterances.py). That is PUSH — Tex
speaking unprompted. It never goes through a model.

This module is the other half: PULL. When a person clicks a spoken line and
asks "what actually happened here," Tex finishes the story in plain
language. That narration MAY be fluent — an LLM is good at turning a sealed
evidence trail into something readable — but it is fenced by hard rules so
it can never undermine the thing Tex sells:

  1. SEALED INPUT ONLY. The model never sees raw agent text or anything
     unsealed. It sees Tex's own sealed facts — counts, verdicts, hashes,
     chain state — assembled here from the stores. This is also the
     prompt-injection fence: a watched agent cannot reach Tex's mouth,
     because Tex's mouth is only ever fed Tex's own sealed numbers.

  2. EXPLAIN, NEVER CLAIM. The model narrates the facts it is given. It is
     instructed to introduce no fact not present, and the structured sealed
     facts + proof anchors ALWAYS travel back with the prose, so nothing is
     taken on the model's word — the reader can check every number.

  3. RECALL, NEVER ADVISE. Tex's interaction law holds here too: a witness
     says what happened and what it saw, never what the client should do.
     The explainer is forbidden from giving recommendations.

  4. DETERMINISTIC FLOOR. If no provider is configured, or the provider
     fails, Tex narrates the same sealed facts with an authored deterministic
     renderer. The system is fully functional, and fully honest, offline.

So: the claim is sealed and deterministic; the explanation is a reading aid
over sealed facts, clearly labeled as such, with the proof attached.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Protocol, runtime_checkable

from tex.vigil.dimensions import ProofRef

__all__ = [
    "ExplanationProvider",
    "ExplanationMode",
    "EvidenceFacts",
    "Explanation",
    "Explainer",
    "build_default_explainer",
]


# --------------------------------------------------------------------------- ports


@runtime_checkable
class ExplanationProvider(Protocol):
    """
    Transport-only contract for a text generator. Tex owns the prompt and
    the grounding rules; the provider owns model execution only.
    """

    def complete(self, *, system_prompt: str, user_prompt: str) -> str:
        """Return plain narration text for the supplied prompt pair."""


class ExplanationMode(str, Enum):
    PRIMARY_PROVIDER = "primary_provider"   # the model narrated
    DEFAULT_FALLBACK = "default_fallback"    # no provider; deterministic floor
    FAILURE_FALLBACK = "failure_fallback"    # provider failed; deterministic floor


# --------------------------------------------------------------------------- facts


@dataclass(frozen=True, slots=True)
class EvidenceFacts:
    """The sealed fact sheet behind one spoken line. The model sees this."""

    dimension: str
    headline: str                       # the one-line sealed fact
    details: list[dict[str, Any]] = field(default_factory=list)
    anchors: list[ProofRef] = field(default_factory=list)

    def is_empty(self) -> bool:
        return not self.details and not self.headline


@dataclass(frozen=True, slots=True)
class Explanation:
    dimension: str
    claim_text: str | None              # the original sealed utterance
    facts: EvidenceFacts
    explanation: str                    # prose (generated or deterministic)
    mode: ExplanationMode
    generator: str                      # provider name, or "deterministic"
    grounded: bool                      # facts + anchors travel with the prose


# --------------------------------------------------------------------------- explainer


_SYSTEM_PROMPT = (
    "You are Tex, an AI-agent governance witness. A person has clicked one "
    "of your sealed observations and asked what happened. You are given a "
    "JSON object of SEALED FACTS that you yourself recorded. Your job is to "
    "narrate those facts in plain, calm language for the person who owns "
    "this system.\n\n"
    "HARD RULES:\n"
    "- Use ONLY the facts in the JSON. Introduce no number, name, time, or "
    "claim that is not present there. If something is not in the facts, do "
    "not mention it.\n"
    "- You are a witness. Say what happened and what you saw. NEVER give "
    "advice, recommendations, next steps, or opinions on what the person "
    "should do.\n"
    "- Do not speculate about causes you were not given.\n"
    "- 2 to 4 sentences. Past tense. No preamble, no headings, no lists.\n"
)


class Explainer:
    """
    Turns a spoken vigil line into a grounded explanation on demand.

    Mirrors the codebase's semantic pattern: an optional provider with a
    deterministic fallback and an explicit execution mode. The deterministic
    renderer is the floor and is always correct, because it only restates
    sealed facts.
    """

    __slots__ = ("_provider", "_allow_fallback", "_provider_name")

    def __init__(
        self,
        *,
        provider: ExplanationProvider | None = None,
        allow_fallback: bool = True,
        provider_name: str | None = None,
    ) -> None:
        self._provider = provider
        self._allow_fallback = allow_fallback
        self._provider_name = provider_name or ("deterministic" if provider is None else "provider")

    def explain(
        self,
        request: Any,
        *,
        dimension: str,
        tenant: str | None,
        claim_text: str | None = None,
    ) -> Explanation:
        facts = _facts_for(request, dimension, tenant)
        deterministic = _render_deterministic(facts)

        if facts.is_empty():
            # Nothing sealed to explain. Never call a model on an empty sheet.
            return Explanation(
                dimension=dimension,
                claim_text=claim_text,
                facts=facts,
                explanation=deterministic,
                mode=ExplanationMode.DEFAULT_FALLBACK,
                generator="deterministic",
                grounded=True,
            )

        if self._provider is None:
            return Explanation(
                dimension=dimension,
                claim_text=claim_text,
                facts=facts,
                explanation=deterministic,
                mode=ExplanationMode.DEFAULT_FALLBACK,
                generator="deterministic",
                grounded=True,
            )

        user_prompt = _build_user_prompt(facts, claim_text)
        try:
            prose = self._provider.complete(
                system_prompt=_SYSTEM_PROMPT, user_prompt=user_prompt
            ).strip()
            if not prose:
                raise ValueError("provider returned empty narration")
            return Explanation(
                dimension=dimension,
                claim_text=claim_text,
                facts=facts,
                explanation=prose,
                mode=ExplanationMode.PRIMARY_PROVIDER,
                generator=self._provider_name,
                grounded=True,
            )
        except Exception:  # noqa: BLE001 — provider transport is untrusted
            if not self._allow_fallback:
                raise
            return Explanation(
                dimension=dimension,
                claim_text=claim_text,
                facts=facts,
                explanation=deterministic,
                mode=ExplanationMode.FAILURE_FALLBACK,
                generator="deterministic",
                grounded=True,
            )


# --------------------------------------------------------------------------- prompt


def _build_user_prompt(facts: EvidenceFacts, claim_text: str | None) -> str:
    payload = {
        "spoken_line": claim_text,
        "sealed_facts": {
            "dimension": facts.dimension,
            "headline": facts.headline,
            "details": facts.details,
            "anchors": [
                {"kind": a.kind, "id": a.id, "sha256": a.sha256, "seq": a.seq}
                for a in facts.anchors
            ],
        },
    }
    return (
        "Narrate these sealed facts for the system owner, following the hard "
        "rules. Facts:\n\n" + json.dumps(payload, indent=2, default=str)
    )


# --------------------------------------------------------------------------- fact assembly
# Detailed sealed reads per dimension. Defensive like dimensions.py: a
# missing or half-initialized store yields an empty sheet, never an error.


def _state(request: Any, name: str) -> Any:
    return getattr(request.app.state, name, None)


def _facts_for(request: Any, dimension: str, tenant: str | None) -> EvidenceFacts:
    builder = _FACT_BUILDERS.get(dimension)
    if builder is None:
        return EvidenceFacts(dimension=dimension, headline="")
    try:
        return builder(request, tenant)
    except Exception:  # noqa: BLE001
        return EvidenceFacts(dimension=dimension, headline="")


def _decisions_by_verdict(request: Any, verdict_name: str, limit: int = 200) -> list[Any]:
    store = _state(request, "decision_store")
    if store is None:
        return []
    from tex.domain.verdict import Verdict

    target = getattr(Verdict, verdict_name)
    recent = store.list_recent(limit=limit)
    return [d for d in recent if getattr(d, "verdict", None) == target]


def _tally(items: list[str]) -> dict[str, int]:
    out: dict[str, int] = {}
    for it in items:
        key = it or "unspecified"
        out[key] = out.get(key, 0) + 1
    return out


def _anchor_decisions(decisions: list[Any], cap: int = 5) -> list[ProofRef]:
    anchors: list[ProofRef] = []
    for d in decisions[:cap]:
        anchors.append(
            ProofRef(
                kind="decision",
                id=str(getattr(d, "decision_id", "") or "") or None,
                sha256=(getattr(d, "evidence_hash", None) or None),
            )
        )
    return anchors


def _facts_execution(request: Any, tenant: str | None) -> EvidenceFacts:
    forbids = _decisions_by_verdict(request, "FORBID")
    by_action = _tally([str(getattr(d, "action_type", "")) for d in forbids])
    by_channel = _tally([str(getattr(d, "channel", "")) for d in forbids])
    return EvidenceFacts(
        dimension="execution",
        headline=f"{len(forbids)} actions were forbidden in the recent window.",
        details=[
            {"forbidden_total": len(forbids)},
            {"by_action_type": by_action},
            {"by_channel": by_channel},
        ],
        anchors=_anchor_decisions(forbids),
    )


def _facts_human_decision(request: Any, tenant: str | None) -> EvidenceFacts:
    abstains = _decisions_by_verdict(request, "ABSTAIN")
    flags: list[str] = []
    for d in abstains:
        flags.extend(str(f) for f in (getattr(d, "uncertainty_flags", None) or []))
    by_action = _tally([str(getattr(d, "action_type", "")) for d in abstains])
    return EvidenceFacts(
        dimension="human_decision",
        headline=f"{len(abstains)} actions are awaiting a human decision.",
        details=[
            {"awaiting_total": len(abstains)},
            {"by_action_type": by_action},
            {"reasons_for_uncertainty": _tally(flags)},
        ],
        anchors=_anchor_decisions(abstains),
    )


def _facts_evidence(request: Any, tenant: str | None) -> EvidenceFacts:
    ledger = _state(request, "discovery_ledger")
    if ledger is None:
        return EvidenceFacts(dimension="evidence", headline="")
    length = len(ledger)
    intact = bool(ledger.verify_chain())
    headline = (
        f"The evidence chain is intact across {length} sealed records."
        if intact
        else f"The evidence chain failed verification; {length} records are affected."
    )
    return EvidenceFacts(
        dimension="evidence",
        headline=headline,
        details=[{"sealed_records": length, "chain_intact": intact}],
        anchors=[ProofRef(kind="evidence_chain", seq=int(length))],
    )


def _facts_identity(request: Any, tenant: str | None) -> EvidenceFacts:
    from tex.api.agent_routes import (
        _build_governance,
        _resolve_discovery_ledger,
        _resolve_ledger,
        _resolve_registry,
    )

    gov = _build_governance(
        registry=_resolve_registry(request),
        action_ledger=_resolve_ledger(request),
        discovery_ledger=_resolve_discovery_ledger(request),
    )
    c = gov.counts
    ungoverned_hr = int(getattr(c, "high_risk_ungoverned", 0) or 0)
    hr_total = int(getattr(c, "high_risk_total", 0) or 0)
    return EvidenceFacts(
        dimension="identity",
        headline=f"{ungoverned_hr} of {hr_total} high-risk agents are acting outside governance.",
        details=[
            {
                "high_risk_ungoverned": ungoverned_hr,
                "high_risk_total": hr_total,
                "governed": int(getattr(c, "governed", 0) or 0),
                "ungoverned": int(getattr(c, "ungoverned", 0) or 0),
                "total_agents": int(getattr(c, "total_agents", 0) or 0),
            }
        ],
        anchors=[
            ProofRef(
                kind="governance_coverage",
                sha256=(getattr(gov, "coverage_root_sha256", "") or None),
            )
        ],
    )


def _facts_monitoring(request: Any, tenant: str | None) -> EvidenceFacts:
    store = _state(request, "connector_health_store")
    if store is None:
        return EvidenceFacts(dimension="monitoring", headline="")
    records = list(
        (store.list_for_tenant(tenant) if tenant else store.list_all()) or []
    )
    failing = [
        {
            "connector": getattr(r, "connector_name", ""),
            "consecutive_failures": int(getattr(r, "consecutive_failures", 0) or 0),
        }
        for r in records
        if int(getattr(r, "consecutive_failures", 0) or 0) > 0
    ]
    return EvidenceFacts(
        dimension="monitoring",
        headline=f"{len(failing)} connectors have stopped reporting.",
        details=failing or [{"failing_connectors": 0}],
        anchors=[
            ProofRef(kind="connector", id=str(f["connector"]) or None)
            for f in failing[:5]
        ],
    )


def _facts_discovery(request: Any, tenant: str | None) -> EvidenceFacts:
    store = _state(request, "scan_run_store")
    if store is None:
        return EvidenceFacts(dimension="discovery", headline="")
    runs = store.list_recent(tenant_id=tenant, limit=1)
    if not runs:
        return EvidenceFacts(dimension="discovery", headline="")
    r = runs[0]
    summary = getattr(r, "summary", None) or {}
    registered = int(summary.get("registered_count") or 0)
    seq_end = getattr(r, "ledger_seq_end", None)
    return EvidenceFacts(
        dimension="discovery",
        headline=f"The most recent scan brought {registered} new agents into view.",
        details=[{"registered_count": registered, "run_id": str(getattr(r, "run_id", "") or "")}],
        anchors=[
            ProofRef(
                kind="scan_run",
                id=str(getattr(r, "run_id", "") or "") or None,
                seq=int(seq_end) if seq_end is not None else None,
            )
        ],
    )


_FACT_BUILDERS = {
    "execution": _facts_execution,
    "human_decision": _facts_human_decision,
    "evidence": _facts_evidence,
    "identity": _facts_identity,
    "monitoring": _facts_monitoring,
    "discovery": _facts_discovery,
}


# --------------------------------------------------------------------------- deterministic floor


def _render_deterministic(facts: EvidenceFacts) -> str:
    """
    The honest floor: restate the sealed facts in plain prose, no model.
    Never speculates, never advises — it only says what was recorded.
    """
    if facts.is_empty():
        return "There is nothing sealed to explain for this line right now."

    parts: list[str] = [facts.headline]

    if facts.dimension == "execution":
        by_action = _first_dict(facts.details, "by_action_type")
        if by_action:
            top = ", ".join(f"{k} ({v})" for k, v in _top_items(by_action, 3))
            parts.append(f"The forbidden actions were mostly: {top}.")
    elif facts.dimension == "human_decision":
        reasons = _first_dict(facts.details, "reasons_for_uncertainty")
        if reasons:
            top = ", ".join(f"{k} ({v})" for k, v in _top_items(reasons, 3))
            parts.append(f"They were held because of: {top}.")
    elif facts.dimension == "identity":
        d = facts.details[0] if facts.details else {}
        parts.append(
            f"In total {d.get('governed', 0)} agents are governed and "
            f"{d.get('ungoverned', 0)} are not."
        )
    elif facts.dimension == "monitoring":
        named = [d for d in facts.details if d.get("connector")]
        if named:
            top = ", ".join(
                f"{d['connector']} ({d['consecutive_failures']} cycles)" for d in named[:3]
            )
            parts.append(f"The silent connectors were: {top}.")

    if facts.anchors:
        a = facts.anchors[0]
        anchor_bits = [b for b in (a.sha256, a.id) if b]
        if anchor_bits:
            parts.append(f"This is sealed under {anchor_bits[0]}.")

    return " ".join(parts)


def _first_dict(details: list[dict[str, Any]], key: str) -> dict[str, Any] | None:
    for d in details:
        if key in d and isinstance(d[key], dict):
            return d[key]
    return None


def _top_items(d: dict[str, Any], n: int) -> list[tuple[str, Any]]:
    return sorted(d.items(), key=lambda kv: kv[1], reverse=True)[:n]


# --------------------------------------------------------------------------- default wiring


def build_default_explainer() -> Explainer:
    """
    Build the explainer from settings, mirroring how the semantic analyzer
    is gated: an OpenAI text provider when TEX_SEMANTIC_PROVIDER='openai'
    and a key is present; otherwise the deterministic floor. Fallback is
    allowed unless explicitly disabled, so the voice's explanation never
    hard-fails on a provider outage.
    """
    try:
        from tex.config import get_settings

        settings = get_settings()
        provider_name = getattr(settings, "semantic_provider", None)
        api_key = getattr(settings, "openai_api_key", None)
        allow_fallback = bool(getattr(settings, "allow_semantic_fallback", True))
        model = getattr(settings, "semantic_model", None) or "gpt-4o-mini"
    except Exception:  # noqa: BLE001
        return Explainer(provider=None, allow_fallback=True)

    if provider_name == "openai" and api_key:
        try:
            from tex.vigil._openai_explainer import OpenAITextProvider

            provider = OpenAITextProvider(api_key=api_key, model=model)
            return Explainer(
                provider=provider, allow_fallback=allow_fallback, provider_name=f"openai:{model}"
            )
        except Exception:  # noqa: BLE001
            return Explainer(provider=None, allow_fallback=True)

    return Explainer(provider=None, allow_fallback=True)
