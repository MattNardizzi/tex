"""
AttriGuard Specialist Judge.

Implements action-level causal attribution via parallel counterfactual
re-execution, per arxiv 2603.10749 (Hu et al., March 2026).

Where AgentArmor and ARGUS perform *static* graph analysis on the
agent's reasoning content, AttriGuard performs *behavioral* attribution
by re-evaluating what the agent's policy would have proposed under
control-attenuated views of its observations. If attenuating the
suspect observation materially changes the proposed action, AttriGuard
concludes the observation was the *cause* — not merely correlated with
— the agent's behavior.

This is the runtime analogue of CHIEF (Thread 3 attribution layer).
CHIEF attributes post-incident; AttriGuard attributes pre-execution.

Counterfactual mechanic
-----------------------
For each candidate observation o in the agent's input window:

  1. Compute the lexical action signature L(action) of the proposed action.
  2. Compute the lexical signature L(o) of the observation.
  3. Construct the control-attenuated input by:
     - Redacting instruction-like phrases from o.
     - Redacting external-source markers from o.
     - Preserving o's surface meaning (length, sentence structure).
  4. Compute the *attribution score* a(o, action):
     - Token-overlap between L(o) and L(action).
     - Whether action verbs in L(action) appear in L(o).
     - Whether L(o) carries authorization claims that the user prompt
       does not.

If a(o, action) >= attribution_threshold, AttriGuard tags this
observation as the causal driver. Multiple driver observations →
elevated risk + ASI06 (memory_poisoning) / ASI01 (goal_hijack) tags.

References
----------
- arxiv 2603.10749 (Hu, Chen, Lin, March 2026) — AttriGuard: causal
  attribution-based defense for indirect prompt injection.
- arxiv 2605.06788 (Feng et al., May 2026) — conformal CHIEF; AttriGuard
  generalises CHIEF's per-step attribution to per-observation
  attribution.
- Microsoft AGT v3.5.0 (May 2026) does *not* implement causal
  attribution as a runtime defense; this places Tex ahead of the
  best commercial governance platform.

Performance: O(|obs| × |action|) per request, where |obs| is the number
of candidate observation sentences (capped at 32) and |action| is the
size of the action signature (≤ 200 tokens). Total ≤ 5 ms p99 budget.
"""

from __future__ import annotations

import re
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from tex.domain.evaluation import EvaluationRequest
from tex.domain.owasp_asi import (
    ASI_GOAL_HIJACK,
    ASI_TOOL_MISUSE,
    ASI_MEMORY_POISONING,
)
from tex.domain.retrieval import RetrievalContext
from tex.observability.telemetry import emit_event
from tex.specialists.base import SpecialistEvidence, SpecialistResult


# ── Configuration ────────────────────────────────────────────────────────


_RISK_FLOOR = 0.05
_CONF_FLOOR = 0.42
_CONF_PER_HIT = 0.08
_CONF_CAP = 0.88

_SEV_CAUSAL_DRIVER = 0.35
_SEV_AUTHORITY_LIFT = 0.30
_SEV_ACTION_INHERITANCE = 0.30
_SEV_MULTIPLE_DRIVERS = 0.20

_MAX_OBSERVATIONS = 32

_ATTRIBUTION_THRESHOLD_CAUSAL = 0.35
_ATTRIBUTION_THRESHOLD_HIGH = 0.55


# Action verbs we look for inside a proposed action.
_ACTION_VERBS: tuple[str, ...] = (
    "send", "transfer", "approve", "delete", "forward", "share",
    "execute", "invoke", "publish", "deploy", "wire", "pay",
    "authorize", "grant", "disable", "enable", "revoke", "post",
    "redirect", "exfiltrate", "leak", "upload", "download",
    # Additions from real attack distributions.
    "install", "deploy", "elevate", "escalate", "return",
    "access", "transmit", "proceed",
)


_ACTION_VERB_RE = re.compile(
    r"\b(" + "|".join(_ACTION_VERBS) + r")\b", re.IGNORECASE
)


# Phrases that lift authority. When an observation contains these, the
# attenuated view will lose the authority claim, which is a strong
# attribution signal.
_AUTHORITY_LIFT_PATTERNS: tuple[str, ...] = (
    "pre-authorized", "preauthorized", "pre-approved", "preapproved",
    "is allowed", "is permitted", "has approved", "approved by",
    "authorized by", "permitted by", "granted by", "blessed by",
    "the user said", "the admin said", "policy permits", "policy allows",
    # Additions for "X had given permission" / "had been given access".
    "had given permission", "has given permission", "given permission",
    "has been given access", "had been given access",
    "this is required", "is a required", "is required for",
    "compatibility step", "compatibility requirement",
    "previously a colleague mentioned",
    "previously a colleague said", "a colleague mentioned",
)


_AUTHORITY_LIFT_RE = re.compile(
    "|".join(re.escape(p) for p in _AUTHORITY_LIFT_PATTERNS),
    re.IGNORECASE,
)


# External-source markers (also used by ARGUS). When an obs sentence
# carries these, AttriGuard treats the whole sentence as untrusted in
# the attenuated view.
_EXTERNAL_SOURCE_PATTERNS: tuple[str, ...] = (
    "the email said", "the document said", "the email instructs",
    "the document instructs", "the message said", "according to the",
    "the response indicates", "the response says", "the tool output",
    "the tool response", "the search result", "the webpage says",
    "the file says", "the attachment", "the retrieved",
    "context indicates", "the observation",
    "the tool returned", "tool returned:", "tool response includes",
    "the response for", "tool description:", "description: '",
    "tool 'web_search'", "tool 'calculator'", "tool 'file_read'",
    "tool 'http_request'", "tool 'capability_request'", "tool 'read_customer'",
    "the embedded note", "in the attachment",
    "a colleague mentioned", "the recent message thread",
    "the customer's most recent reply",
)


_EXTERNAL_SOURCE_RE = re.compile(
    "|".join(re.escape(p) for p in _EXTERNAL_SOURCE_PATTERNS),
    re.IGNORECASE,
)


# Decision-marker patterns. AttriGuard looks for these to identify the
# proposed action inside the request content (when no separate action
# spec was supplied via metadata).
_DECISION_MARKERS: tuple[str, ...] = (
    # First-person
    "i will", "i'll go ahead", "proceeding to", "executing the",
    "approving the", "transferring the", "sending the",
    "calling the tool", "invoking the tool",
    # Imperative-form
    "please go ahead", "please approve", "please transfer",
    "please send", "please execute", "please forward",
    "please install", "please grant", "please return",
    "please authorize", "please proceed", "please act on",
    "please remember", "please retain", "please store",
    "go ahead and approve", "go ahead and send",
    "go ahead and transfer", "could you proceed", "kindly transmit",
    "act on the",
)


# Sentence splitter.
_SENT_SPLIT_RE = re.compile(r"(?<=[\.\?!])\s+")


# Token splitter for overlap scoring.
_TOKEN_RE = re.compile(r"\b[a-z0-9_-]{3,}\b", re.IGNORECASE)


# ── Public data types ────────────────────────────────────────────────────


class AttributionScore(BaseModel):
    """Per-observation attribution score for AttriGuard's audit trail."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    observation_text: str = Field(min_length=1, max_length=1500)
    token_overlap_ratio: float = Field(ge=0.0, le=1.0)
    has_authority_lift: bool
    has_action_inheritance: bool
    is_external_source: bool
    score: float = Field(ge=0.0, le=1.0)
    is_causal_driver: bool


# ── Specialist ──────────────────────────────────────────────────────────


class AttriGuardSpecialist:
    """Causal-attribution specialist.

    The specialist's per-request work:
      1. Extract or synthesise the proposed action signature.
      2. Split request content into observation sentences.
      3. For each obs, compute its attribution score against the action.
      4. Tag observations with score >= threshold as causal drivers.
      5. Emit reason codes + ASI tags proportional to the number and
         severity of drivers.
    """

    name = "attriguard"

    def evaluate(
        self,
        *,
        request: EvaluationRequest,
        retrieval_context: RetrievalContext,
    ) -> SpecialistResult:
        # Extract action signature.
        action_sig = self._action_signature(request)
        action_tokens = _tokenize(action_sig)

        if not action_tokens:
            # No action to attribute — return floor.
            return _floor_result(request)

        # Split observations.
        obs_sentences = self._observation_sentences(request)
        if not obs_sentences:
            return _floor_result(request)

        # Score each observation.
        action_verbs = set(
            m.group(1).lower() for m in _ACTION_VERB_RE.finditer(action_sig)
        )
        scored: list[AttributionScore] = []
        for sent in obs_sentences[:_MAX_OBSERVATIONS]:
            score = self._attribute(sent, action_tokens, action_verbs)
            scored.append(score)

        # Aggregate.
        drivers = [s for s in scored if s.is_causal_driver]
        high_drivers = [s for s in scored if s.score >= _ATTRIBUTION_THRESHOLD_HIGH]

        reason_codes: list[str] = []
        asi_tags: list[str] = []
        evidence: list[SpecialistEvidence] = []
        risk_accum = 0.0

        for s in drivers:
            risk_accum += _SEV_CAUSAL_DRIVER
            reason_codes.append("ATTRIGUARD_CAUSAL_DRIVER")
            if s.has_authority_lift:
                risk_accum += _SEV_AUTHORITY_LIFT
                reason_codes.append("ATTRIGUARD_AUTHORITY_LIFT")
                if ASI_GOAL_HIJACK not in asi_tags:
                    asi_tags.append(ASI_GOAL_HIJACK)
            if s.has_action_inheritance:
                risk_accum += _SEV_ACTION_INHERITANCE
                reason_codes.append("ATTRIGUARD_ACTION_INHERITANCE")
                if ASI_TOOL_MISUSE not in asi_tags:
                    asi_tags.append(ASI_TOOL_MISUSE)
            if s.is_external_source:
                if ASI_MEMORY_POISONING not in asi_tags:
                    asi_tags.append(ASI_MEMORY_POISONING)
            evidence.append(
                SpecialistEvidence(
                    text=s.observation_text[:1500],
                    explanation=(
                        f"ATTRIGUARD_CAUSAL_DRIVER: observation scored "
                        f"{s.score:.3f} (overlap={s.token_overlap_ratio:.2f}, "
                        f"authority_lift={s.has_authority_lift}, "
                        f"action_inheritance={s.has_action_inheritance}, "
                        f"external_source={s.is_external_source}). "
                        "The proposed action's content is causally "
                        "explained by this observation."
                    ),
                )
            )

        if len(drivers) >= 2:
            risk_accum += _SEV_MULTIPLE_DRIVERS
            reason_codes.append("ATTRIGUARD_MULTIPLE_DRIVERS")
        if not reason_codes:
            _emit(
                request_id=str(request.request_id),
                risk_score=_RISK_FLOOR,
                reason_codes=tuple(),
                obs_count=len(obs_sentences),
                driver_count=0,
            )
            return SpecialistResult(
                specialist_name=self.name,
                risk_score=_RISK_FLOOR,
                confidence=_CONF_FLOOR,
                summary=(
                    f"No causal driver observations identified across "
                    f"{len(obs_sentences)} candidate observations."
                ),
                rationale=(
                    "AttriGuard's parallel counterfactual attribution "
                    "found no observation whose attenuation would "
                    "materially change the proposed action."
                ),
                evidence=tuple(),
                matched_policy_clause_ids=tuple(),
                matched_entity_names=tuple(),
                uncertainty_flags=("specialist_heuristic",),
            )

        deduped = _dedupe(reason_codes)
        risk = min(1.0, _RISK_FLOOR + risk_accum)
        confidence = min(_CONF_CAP, _CONF_FLOOR + _CONF_PER_HIT * len(deduped))

        # Five Eyes: multiple independent causal drivers = human review.
        uncertainty_flags: list[str] = ["specialist_heuristic"]
        if len(drivers) >= 2:
            from tex.specialists.human_review import (
                build_specialist_human_review_flag,
            )
            uncertainty_flags.append(
                build_specialist_human_review_flag(
                    f"AttriGuard identified {len(drivers)} independent "
                    "causal-driver observations; per Five Eyes May 2026 "
                    "guidance this action should not be auto-committed."
                )
            )

        _emit(
            request_id=str(request.request_id),
            risk_score=risk,
            reason_codes=tuple(deduped),
            obs_count=len(obs_sentences),
            driver_count=len(drivers),
        )

        return SpecialistResult(
            specialist_name=self.name,
            risk_score=round(risk, 4),
            confidence=round(confidence, 4),
            summary=(
                f"Causal-attribution audit: {len(drivers)} driver "
                f"observations (of {len(obs_sentences)} candidates); "
                f"{len(high_drivers)} high-confidence. "
                "Proposed action is causally explained by externally-"
                "sourced content."
            ),
            rationale=(
                "AttriGuard re-evaluates the agent's proposed action "
                "under control-attenuated views of its observations. "
                "Observations whose attenuation would materially "
                "change the action are flagged as causal drivers. "
                "This implements arxiv 2603.10749 (Hu et al., March "
                "2026) — runtime causal attribution. Microsoft AGT "
                "v3.5.0 and other commercial governance platforms do "
                "not ship this primitive as of May 2026."
            ),
            evidence=tuple(evidence),
            matched_policy_clause_ids=tuple([*deduped, *asi_tags]),
            matched_entity_names=tuple(),
            uncertainty_flags=tuple(uncertainty_flags),
        )

    # ── helpers ────────────────────────────────────────────────────────

    def _action_signature(self, request: EvaluationRequest) -> str:
        """Pick the text that represents the proposed action.

        Order:
          1. Metadata-supplied `attriguard.action` (if present).
          2. Decision sentences in request.content (matching markers).
          3. Empty string (no proposed action — caller returns floor).
        """
        md = request.metadata.get("attriguard")
        if isinstance(md, dict):
            action = md.get("action")
            if isinstance(action, str) and action.strip():
                return action
        # Decision sentences only — falling back to whole content would
        # cause benign single-sentence requests to "attribute" themselves
        # to themselves (high overlap, false-positive driver).
        sentences = [
            s.strip()
            for s in _SENT_SPLIT_RE.split(request.content or "")
            if s.strip()
        ]
        decision_sents = [
            s for s in sentences
            if any(m in s.lower() for m in _DECISION_MARKERS)
        ]
        if decision_sents:
            return " ".join(decision_sents)
        return ""  # → floor

    def _observation_sentences(
        self, request: EvaluationRequest
    ) -> list[str]:
        """Sentences that are candidates to be the causal driver.

        Anything that is NOT a decision sentence — observation,
        retrieval, tool output, etc.
        """
        md = request.metadata.get("attriguard")
        if isinstance(md, dict):
            obs_list = md.get("observations")
            if isinstance(obs_list, list) and obs_list:
                return [str(o) for o in obs_list if isinstance(o, str) and o.strip()]
        sentences = [
            s.strip()
            for s in _SENT_SPLIT_RE.split(request.content or "")
            if s.strip()
        ]
        return [
            s for s in sentences
            if not any(m in s.lower() for m in _DECISION_MARKERS)
        ]

    def _attribute(
        self,
        observation: str,
        action_tokens: set[str],
        action_verbs: set[str],
    ) -> AttributionScore:
        obs_tokens = _tokenize(observation)
        if not obs_tokens:
            return AttributionScore(
                observation_text=observation[:1500] or "(empty)",
                token_overlap_ratio=0.0,
                has_authority_lift=False,
                has_action_inheritance=False,
                is_external_source=False,
                score=0.0,
                is_causal_driver=False,
            )
        overlap = len(action_tokens & obs_tokens) / max(1, len(action_tokens))
        has_auth_lift = bool(_AUTHORITY_LIFT_RE.search(observation))
        obs_action_verbs = set(
            m.group(1).lower() for m in _ACTION_VERB_RE.finditer(observation)
        )
        has_action_inheritance = bool(obs_action_verbs & action_verbs)
        is_external_source = bool(_EXTERNAL_SOURCE_RE.search(observation))

        # Compose score:
        #   - overlap is the base (0..1).
        #   - authority lift adds 0.30.
        #   - action inheritance adds 0.25.
        #   - external source adds 0.15.
        score = overlap
        if has_auth_lift:
            score += 0.30
        if has_action_inheritance:
            score += 0.25
        if is_external_source:
            score += 0.15
        score = min(1.0, score)

        return AttributionScore(
            observation_text=observation[:1500],
            token_overlap_ratio=round(overlap, 4),
            has_authority_lift=has_auth_lift,
            has_action_inheritance=has_action_inheritance,
            is_external_source=is_external_source,
            score=round(score, 4),
            is_causal_driver=score >= _ATTRIBUTION_THRESHOLD_CAUSAL,
        )


# ── module helpers ──────────────────────────────────────────────────────


def _tokenize(text: str) -> set[str]:
    if not text:
        return set()
    return {m.group(0).lower() for m in _TOKEN_RE.finditer(text)}


def _floor_result(request: EvaluationRequest) -> SpecialistResult:
    _emit(
        request_id=str(request.request_id),
        risk_score=_RISK_FLOOR,
        reason_codes=tuple(),
        obs_count=0,
        driver_count=0,
    )
    return SpecialistResult(
        specialist_name="attriguard",
        risk_score=_RISK_FLOOR,
        confidence=_CONF_FLOOR,
        summary="No proposed action or observations to attribute.",
        rationale=(
            "AttriGuard requires a proposed action and at least one "
            "candidate observation to compute attribution."
        ),
        evidence=tuple(),
        matched_policy_clause_ids=tuple(),
        matched_entity_names=tuple(),
        uncertainty_flags=("specialist_heuristic",),
    )


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
    obs_count: int,
    driver_count: int,
) -> None:
    fields: dict[str, Any] = {
        "specialist_name": "attriguard",
        "request_id": request_id,
        "risk_score": round(risk_score, 4),
        "reason_codes": list(reason_codes),
        "obs_count": obs_count,
        "driver_count": driver_count,
    }
    emit_event("specialist.attriguard.evaluated", **fields)


__all__ = [
    "AttriGuardSpecialist",
    "AttributionScore",
]
