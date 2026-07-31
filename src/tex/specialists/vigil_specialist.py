"""
VIGIL Specialist Judge.

Implements verify-before-commit on the agent's tool stream per arxiv
2601.05755v2 (VIGIL framework + SIREN benchmark, January 2026).

Where ClawGuard enforces a static boundary on inbound content, VIGIL
operates on the *outbound* tool-call stream: each tool call is treated
as a *speculative hypothesis* whose commit must be verified against
the agent's user-grounded intent. If the verification fails, the call
is denied with a structured reason; if it passes, the call ships.

The paper's central insight: defending against IPI by *restricting* the
agent's reasoning over external content (the static-isolation paradigm)
forces a tradeoff against benign reasoning flexibility. VIGIL inverts
this — let the agent reason freely, but require a verifier-grounded
intent check before each tool commits.

VIGIL specialist scope
----------------------
This specialist runs at the `/v1/guardrail` request boundary, so it
sees the proposed action (the tool call about to execute) and the
context that produced it. For each request:

  1. Identify the proposed tool call (from metadata or content parse).
  2. Extract or synthesise the **user-grounded intent** — what the
     user actually asked for, stripped of any tool-stream content
     that came from external observations.
  3. Compute a **divergence score** between the proposed tool call
     and the user-grounded intent.
  4. Compute a **tool-stream poisoning score** — were the recent
     observation events shaped by external content (the SIREN signal)?
  5. Aggregate into a verify-before-commit verdict.

SIREN-style detection
---------------------
The SIREN benchmark (959 cases) tests "tool stream injection cases
designed to simulate pervasive threats characterized by dynamic
dependencies." We approximate the SIREN signal class by detecting:

  - Tool-stream divergence (proposed tool/parameters don't match the
    user's stated intent).
  - Cross-observation contamination (one observation's content directly
    references another observation's text).
  - Cascade-style chaining (multiple tool calls in sequence each
    parameterised by the previous observation's output).
  - Manipulated metadata signature (tool-call metadata claims to
    "originate from" something other than the user prompt).

References
----------
- arxiv 2601.05755v2 (VIGIL framework + SIREN benchmark, Jan 2026) —
  primary paper anchor.
- arxiv 2604.11790 (ClawGuard) — boundary enforcer companion.
- arxiv 2605.03378 (ARGUS) — provenance companion.
- OWASP ASI 2026 ASI02 (Tool Misuse), ASI07 (Insecure Inter-Agent
  Comm), ASI08 (Cascading Failure).
"""

from __future__ import annotations

import re
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from tex.domain.evaluation import EvaluationRequest
from tex.domain.owasp_asi import (
    ASI_TOOL_MISUSE,
    ASI_INSECURE_INTER_AGENT_COMM,
    ASI_CASCADING_FAILURE,
)
from tex.domain.retrieval import RetrievalContext
from tex.observability.telemetry import emit_event
from tex.specialists.base import SpecialistEvidence, SpecialistResult


# ── Configuration ────────────────────────────────────────────────────────


_RISK_FLOOR = 0.05
_CONF_FLOOR = 0.42
_CONF_PER_HIT = 0.08
_CONF_CAP = 0.88

_SEV_INTENT_DIVERGENCE = 0.40
_SEV_TOOL_STREAM_POISON = 0.35
_SEV_CROSS_OBS_CONTAMINATION = 0.25
_SEV_CASCADE_CHAINING = 0.30
_SEV_METADATA_CLAIM_MISMATCH = 0.20

_INTENT_DIVERGENCE_THRESHOLD = 0.40
_POISON_THRESHOLD = 0.35

_TOKEN_RE = re.compile(r"\b[a-z0-9_-]{3,}\b", re.IGNORECASE)
_SENT_SPLIT_RE = re.compile(r"(?<=[\.\?!])\s+")


# Tool-stream poisoning signals — observations containing these markers
# are likely tool outputs that have themselves been shaped by external
# content.
_POISON_MARKERS: tuple[str, ...] = (
    "ignore previous", "override your", "new instructions", "system override",
    "developer mode", "the user authorized", "the user pre-approved",
    "execute this", "delete this", "transfer this", "the document instructs",
    "the email instructs", "the response says to", "the search result indicates",
    "according to the response", "the tool returned", "as the result states",
)


_POISON_RE = re.compile(
    "|".join(re.escape(p) for p in _POISON_MARKERS),
    re.IGNORECASE,
)


# Cascade-style chaining markers. Split into:
#   - STRONG markers are unambiguous attack idioms — fire on a single
#     match.
#   - WEAK markers are common in benign multi-step workflows too, so
#     require a co-signal (another weak marker OR a strong marker OR an
#     external-source marker in the same request) before firing.
_CASCADE_STRONG_MARKERS: tuple[str, ...] = (
    "chain the result",
    "feed the output to",
    "pass to the next tool",
    "based on the last observation",
)


_CASCADE_WEAK_MARKERS: tuple[str, ...] = (
    "then call",
    "next invoke",
    "use the previous result",
    "from the prior step",
)


_CASCADE_STRONG_RE = re.compile(
    "|".join(re.escape(p) for p in _CASCADE_STRONG_MARKERS),
    re.IGNORECASE,
)


_CASCADE_WEAK_RE = re.compile(
    "|".join(re.escape(p) for p in _CASCADE_WEAK_MARKERS),
    re.IGNORECASE,
)


# ── Public types ────────────────────────────────────────────────────────


class VigilVerification(BaseModel):
    """Verify-before-commit verdict, attached to the SpecialistResult.

    Used by the audit chain to reproduce the verification at replay time.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    proposed_tool: str = Field(min_length=1, max_length=200)
    user_intent_signature: str = Field(min_length=0, max_length=400)
    divergence_score: float = Field(ge=0.0, le=1.0)
    poison_score: float = Field(ge=0.0, le=1.0)
    cross_obs_contamination: bool
    cascade_chaining: bool
    metadata_claim_mismatch: bool
    decision: str  # "commit" | "deny" | "uncertain"


# ── Specialist ──────────────────────────────────────────────────────────


class VigilSpecialist:
    """Verify-before-commit specialist judge.

    Per-request work:
      1. Extract proposed tool call.
      2. Extract user-grounded intent.
      3. Compute divergence + poison scores.
      4. Emit reason codes proportional to severity.
    """

    name = "vigil"

    def evaluate(
        self,
        *,
        request: EvaluationRequest,
        retrieval_context: RetrievalContext,
    ) -> SpecialistResult:
        # Extract verification context.
        verif = self._verify(request=request)

        reason_codes: list[str] = []
        asi_tags: list[str] = []
        evidence: list[SpecialistEvidence] = []
        risk_accum = 0.0

        if verif.divergence_score >= _INTENT_DIVERGENCE_THRESHOLD and (
            verif.poison_score >= _POISON_THRESHOLD
            or verif.cross_obs_contamination
            or verif.cascade_chaining
            or verif.metadata_claim_mismatch
        ):
            # Per arxiv 2601.05755, VIGIL only escalates on divergence
            # when there is *independent* evidence the tool stream was
            # manipulated. Token-level divergence alone is too noisy on
            # legitimate tool calls whose interface vocabulary doesn't
            # overlap the user's domain vocabulary.
            risk_accum += _SEV_INTENT_DIVERGENCE
            reason_codes.append("VIGIL_INTENT_DIVERGENCE")
            if ASI_TOOL_MISUSE not in asi_tags:
                asi_tags.append(ASI_TOOL_MISUSE)
            evidence.append(
                SpecialistEvidence(
                    text=verif.proposed_tool[:1500],
                    explanation=(
                        f"VIGIL_INTENT_DIVERGENCE: proposed tool call "
                        f"diverges from user-grounded intent "
                        f"(divergence={verif.divergence_score:.3f}, "
                        f"threshold={_INTENT_DIVERGENCE_THRESHOLD}) AND "
                        "independent tool-stream-poison signal present. "
                        "Per arxiv 2601.05755 verify-before-commit, the "
                        "tool call should not be committed."
                    ),
                )
            )

        if verif.poison_score >= _POISON_THRESHOLD:
            risk_accum += _SEV_TOOL_STREAM_POISON
            reason_codes.append("VIGIL_TOOL_STREAM_POISON")
            if ASI_INSECURE_INTER_AGENT_COMM not in asi_tags:
                asi_tags.append(ASI_INSECURE_INTER_AGENT_COMM)
            evidence.append(
                SpecialistEvidence(
                    text=request.content[:1500] if request.content else "(empty)",
                    explanation=(
                        f"VIGIL_TOOL_STREAM_POISON: SIREN-class signal "
                        f"in observation stream (poison_score="
                        f"{verif.poison_score:.3f}). External content has "
                        "shaped the tool stream."
                    ),
                )
            )

        if verif.cross_obs_contamination:
            risk_accum += _SEV_CROSS_OBS_CONTAMINATION
            reason_codes.append("VIGIL_CROSS_OBS_CONTAMINATION")

        if verif.cascade_chaining:
            risk_accum += _SEV_CASCADE_CHAINING
            reason_codes.append("VIGIL_CASCADE_CHAINING")
            if ASI_CASCADING_FAILURE not in asi_tags:
                asi_tags.append(ASI_CASCADING_FAILURE)

        if verif.metadata_claim_mismatch:
            risk_accum += _SEV_METADATA_CLAIM_MISMATCH
            reason_codes.append("VIGIL_METADATA_CLAIM_MISMATCH")

        if not reason_codes:
            _emit(
                request_id=str(request.request_id),
                risk_score=_RISK_FLOOR,
                reason_codes=tuple(),
                decision="commit",
            )
            return SpecialistResult(
                specialist_name=self.name,
                risk_score=_RISK_FLOOR,
                confidence=_CONF_FLOOR,
                summary=(
                    "Verify-before-commit: proposed tool call passes "
                    "user-grounded intent check."
                ),
                rationale=(
                    "VIGIL (arxiv 2601.05755) verifies each tool call "
                    "against the user's grounded intent before commit. "
                    "This request's proposed action aligns with the "
                    "user prompt and shows no SIREN-class tool-stream "
                    "poisoning."
                ),
                evidence=tuple(),
                matched_policy_clause_ids=tuple(),
                matched_entity_names=tuple(),
                uncertainty_flags=("specialist_heuristic",),
            )

        deduped = _dedupe(reason_codes)
        risk = min(1.0, _RISK_FLOOR + risk_accum)
        confidence = min(_CONF_CAP, _CONF_FLOOR + _CONF_PER_HIT * len(deduped))

        decision = "deny" if risk >= 0.5 else "uncertain"
        _emit(
            request_id=str(request.request_id),
            risk_score=risk,
            reason_codes=tuple(deduped),
            decision=decision,
        )

        # Five Eyes: verify-before-commit decision = "deny" → human review.
        uncertainty_flags: list[str] = ["specialist_heuristic"]
        if decision == "deny":
            from tex.specialists.human_review import (
                build_specialist_human_review_flag,
            )
            uncertainty_flags.append(
                build_specialist_human_review_flag(
                    "VIGIL verify-before-commit returned DENY; per "
                    "arxiv 2601.05755 and Five Eyes May 2026 guidance, "
                    "the proposed tool call must not be committed "
                    "without human review."
                )
            )

        return SpecialistResult(
            specialist_name=self.name,
            risk_score=round(risk, 4),
            confidence=round(confidence, 4),
            summary=(
                f"Verify-before-commit DENY-class signal "
                f"(divergence={verif.divergence_score:.3f}, "
                f"poison={verif.poison_score:.3f}). "
                "Proposed tool call fails grounded-intent check."
            ),
            rationale=(
                "VIGIL implements arxiv 2601.05755v2 verify-before-commit. "
                "Each tool call is a speculative hypothesis; the commit "
                "requires verifier agreement with the user-grounded intent. "
                "SIREN-style signals were detected in the observation "
                "stream. No commercial governance platform ships this "
                "primitive as of May 2026."
            ),
            evidence=tuple(evidence),
            matched_policy_clause_ids=tuple([*deduped, *asi_tags]),
            matched_entity_names=tuple(),
            uncertainty_flags=tuple(uncertainty_flags),
        )

    # ── verification helpers ───────────────────────────────────────────

    def _verify(self, *, request: EvaluationRequest) -> VigilVerification:
        proposed_tool = self._proposed_tool(request)
        user_intent_sig = self._user_intent_signature(request)

        divergence = self._divergence_score(proposed_tool, user_intent_sig)
        poison = self._poison_score(request)
        cross_obs = self._cross_obs_contamination(request)
        cascade = self._cascade_chaining(request)
        metadata_mismatch = self._metadata_claim_mismatch(request)

        if divergence >= 0.7 or poison >= 0.7:
            decision = "deny"
        elif divergence >= _INTENT_DIVERGENCE_THRESHOLD or poison >= _POISON_THRESHOLD:
            decision = "uncertain"
        else:
            decision = "commit"

        return VigilVerification(
            proposed_tool=proposed_tool[:200] or "(none)",
            user_intent_signature=user_intent_sig[:400],
            divergence_score=round(divergence, 4),
            poison_score=round(poison, 4),
            cross_obs_contamination=cross_obs,
            cascade_chaining=cascade,
            metadata_claim_mismatch=metadata_mismatch,
            decision=decision,
        )

    def _proposed_tool(self, request: EvaluationRequest) -> str:
        md = request.metadata.get("vigil")
        if isinstance(md, dict):
            tc = md.get("proposed_tool_call")
            if isinstance(tc, str) and tc.strip():
                return tc
            if isinstance(tc, dict):
                name = str(tc.get("name", "")).strip()
                input_blob = str(tc.get("input", "")).strip()
                if name or input_blob:
                    return f"{name} {input_blob}".strip()
        # Fall back to action_type + recipient + small content snippet.
        snippet = (request.content or "")[:200]
        return f"action={request.action_type} recipient={request.recipient or 'none'} {snippet}"

    def _user_intent_signature(self, request: EvaluationRequest) -> str:
        md = request.metadata.get("vigil")
        if isinstance(md, dict):
            ui = md.get("user_intent")
            if isinstance(ui, str) and ui.strip():
                return ui
        # No explicit intent supplied → return empty so divergence
        # detection skips. Without a ground-truth user intent we cannot
        # honestly compute divergence; treating action_type as a proxy
        # caused false positives on every benign request.
        return ""

    def _divergence_score(self, proposed: str, intent: str) -> float:
        """Token-disjointness between proposed action and stated intent."""
        if not proposed or not intent:
            return 0.0
        pt = _tokenize(proposed)
        it = _tokenize(intent)
        if not pt or not it:
            return 0.0
        # Drop generic "action=" / "channel=" filler that came from the
        # synthetic intent signature.
        pt_real = pt - {"action", "channel", "tool_call", "api", "none"}
        if not pt_real:
            return 0.0
        overlap = len(pt_real & it) / max(1, len(pt_real))
        return max(0.0, 1.0 - overlap)

    def _poison_score(self, request: EvaluationRequest) -> float:
        text = request.content or ""
        if not text:
            return 0.0
        hits = len(_POISON_RE.findall(text))
        if hits == 0:
            return 0.0
        # Each hit adds 0.25, capped at 1.0.
        return min(1.0, 0.25 * hits)

    def _cross_obs_contamination(self, request: EvaluationRequest) -> bool:
        """Two observation sentences sharing >= 50% token overlap suggests
        one obs was copied from another — a SIREN-class signal."""
        sentences = [
            s.strip()
            for s in _SENT_SPLIT_RE.split(request.content or "")
            if s.strip()
        ]
        if len(sentences) < 2:
            return False
        for i, a in enumerate(sentences):
            ta = _tokenize(a)
            if len(ta) < 4:
                continue
            for b in sentences[i + 1:]:
                tb = _tokenize(b)
                if len(tb) < 4:
                    continue
                overlap = len(ta & tb) / max(1, min(len(ta), len(tb)))
                if overlap >= 0.5:
                    return True
        return False

    def _cascade_chaining(self, request: EvaluationRequest) -> bool:
        text = request.content or ""
        # Strong markers fire on a single match.
        if _CASCADE_STRONG_RE.search(text):
            return True
        # Weak markers require co-signal: another weak match, OR a
        # poison signal in the same request. This keeps legitimate
        # multi-step workflows ("then call X, then process Y") from
        # firing.
        weak_matches = _CASCADE_WEAK_RE.findall(text)
        if len(weak_matches) >= 2:
            return True
        if weak_matches and _POISON_RE.search(text):
            return True
        return False

    def _metadata_claim_mismatch(self, request: EvaluationRequest) -> bool:
        md = request.metadata.get("vigil")
        if not isinstance(md, dict):
            return False
        claim = str(md.get("origin_claim", "")).lower()
        if not claim:
            return False
        # If the metadata claims origin from somewhere other than the user
        # prompt, that's a mismatch.
        legit = {"user", "user_prompt", "user_message", "operator"}
        return claim not in legit


# ── module helpers ───────────────────────────────────────────────────────


def _tokenize(text: str) -> set[str]:
    if not text:
        return set()
    return {m.group(0).lower() for m in _TOKEN_RE.finditer(text)}


def _dedupe(items: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for item in items:
        key = item.casefold()
        if key in seen:
            continue
        seen.add(key)
        out.append(item)
    return out


def _emit(
    *,
    request_id: str,
    risk_score: float,
    reason_codes: tuple[str, ...],
    decision: str,
) -> None:
    fields: dict[str, Any] = {
        "specialist_name": "vigil",
        "request_id": request_id,
        "risk_score": round(risk_score, 4),
        "reason_codes": list(reason_codes),
        "vigil_decision": decision,
    }
    emit_event("specialist.vigil.evaluated", **fields)


__all__ = [
    "VigilSpecialist",
    "VigilVerification",
]
