"""
Behavioral evaluation stream.

Answers: is what this agent is doing now consistent with how it has
been behaving over time? Produces a deviation score relative to the
agent's behavioral baseline derived from the action ledger.

For agents with no ledger history, returns a cold-start signal — low
confidence, neutral risk, with an explicit `cold_start` flag so the
router can take the absence of history into account.

V11: this evaluator now optionally consults a *tenant* content
baseline as well. When wired, it folds two cross-agent signals into
the existing behavioral signal:

  - tenant_novel_content: the outbound content's MinHash signature
    is far from anything any agent in the same tenant has previously
    PERMITted on this action_type
  - tenant_novel_recipient_domain: the recipient domain is unseen
    tenant-wide for this action_type

The tenant baseline is intentionally consulted *here* rather than in
a brand-new top-level stream because tenant-scope novelty is
behavioral drift at tenant scope — same shape, broader lens.
Integrating it into the existing behavioral signal keeps the seven-
stream fusion architecture intact and lets the existing fingerprint
contract (no agent => bit-for-bit legacy reproduction) hold.
"""

from __future__ import annotations

from uuid import UUID

from tex.domain.agent import (
    AgentIdentity,
    BehavioralBaseline,
)
from tex.domain.agent_signal import BehavioralSignal
from tex.domain.evaluation import EvaluationRequest
from tex.domain.finding import Finding
from tex.domain.severity import Severity
from tex.domain.tenant_baseline import (
    TenantContentBaselineLookup,
    compute_content_signature,
)
from tex.stores.action_ledger import InMemoryActionLedger
from tex.stores.tenant_content_baseline import InMemoryTenantContentBaseline


# Agents with fewer than this many ledger entries are considered
# cold-start. We have enough history to compute distributions but not
# enough to draw confident conclusions.
_MIN_SAMPLE_FOR_FULL_CONFIDENCE = 25

# Recent-window for "is the agent currently abstaining a lot."
_RECENT_WINDOW = 20

# Thresholds at which tenant-scope novelty becomes a real finding.
# These are conservative defaults; the policy layer can override them
# in a future revision without changing this file.
_TENANT_NOVEL_FINDING_THRESHOLD = 0.85
_TENANT_NOVEL_UNCERTAINTY_THRESHOLD = 0.65


class AgentBehavioralEvaluator:
    """
    Pure-with-respect-to-its-inputs evaluator.

    The evaluator does not own the ledger or the tenant baseline — it
    reads from ones supplied at construction time. This keeps testing
    easy and matches Tex's pattern of stateless layers reading from
    immutable inputs.

    The tenant baseline is optional. When None, the evaluator behaves
    exactly as the V10 behavioral evaluator did.
    """

    __slots__ = ("_ledger", "_window", "_tenant_baseline")

    def __init__(
        self,
        *,
        ledger: InMemoryActionLedger,
        window: int = 200,
        tenant_baseline: InMemoryTenantContentBaseline | None = None,
    ) -> None:
        self._ledger = ledger
        self._window = window
        self._tenant_baseline = tenant_baseline

    def evaluate(
        self,
        *,
        agent: AgentIdentity,
        request: EvaluationRequest,
    ) -> BehavioralSignal:
        baseline = self._ledger.compute_baseline(agent.agent_id, window=self._window)
        recent = self._ledger.list_for_agent(agent.agent_id, limit=_RECENT_WINDOW)
        recent_abstain_rate = (
            sum(1 for e in recent if e.verdict.upper() == "ABSTAIN") / len(recent)
            if recent
            else 0.0
        )

        # Compute the tenant-scope content lookup once. The lookup is a
        # neutral cold-start when no baseline is wired or when the
        # tenant has no PERMITted history yet on this action_type.
        tenant_lookup = self._lookup_tenant(agent=agent, request=request)

        if baseline.is_empty:
            return _cold_start_signal(
                agent.agent_id,
                recent_abstain_rate,
                tenant_lookup,
            )

        deviation_components: dict[str, float] = {}
        findings: list[Finding] = []
        reasons: list[str] = []
        uncertainty_flags: list[str] = []

        # 1. Novel-action deviation. If the agent has never done this
        #    action_type before, that is a behavioral drift signal.
        action_freq = baseline.action_type_distribution.get(
            request.action_type, 0.0
        )
        novel_action = action_freq == 0.0
        deviation_components["novel_action_type"] = 0.55 if novel_action else max(
            0.0, 0.30 - 2 * action_freq
        )

        # 2. Novel channel. Same idea for channel.
        channel_freq = baseline.channel_distribution.get(request.channel, 0.0)
        novel_channel = channel_freq == 0.0
        deviation_components["novel_channel"] = 0.45 if novel_channel else max(
            0.0, 0.20 - 2 * channel_freq
        )

        # 3. Novel recipient domain (per-agent).
        novel_recipient = False
        if request.recipient:
            domain = _domain_of(request.recipient)
            if domain:
                domain_freq = baseline.recipient_domain_distribution.get(domain, 0.0)
                novel_recipient = domain_freq == 0.0
                deviation_components["novel_recipient_domain"] = (
                    0.40 if novel_recipient else max(0.0, 0.20 - 2 * domain_freq)
                )
            else:
                deviation_components["novel_recipient_domain"] = 0.10
        else:
            deviation_components["novel_recipient_domain"] = 0.0

        # 4. Forbid streak. If the agent is on a multi-FORBID streak,
        #    something is wrong upstream. Strong signal.
        if baseline.forbid_streak >= 3:
            streak_score = min(1.0, 0.50 + 0.15 * (baseline.forbid_streak - 3))
            findings.append(
                Finding(
                    source="agent.behavioral",
                    rule_name="forbid_streak",
                    severity=Severity.CRITICAL if baseline.forbid_streak >= 5 else Severity.WARNING,
                    message=(
                        f"Agent has produced {baseline.forbid_streak} consecutive "
                        "FORBID verdicts. Investigate upstream agent behavior."
                    ),
                )
            )
            reasons.append(
                f"Agent on FORBID streak of {baseline.forbid_streak}; behavioral risk elevated."
            )
            uncertainty_flags.append("forbid_streak")
        elif baseline.forbid_streak == 2:
            streak_score = 0.30
            uncertainty_flags.append("recent_forbid_streak")
        else:
            streak_score = 0.0
        deviation_components["forbid_streak"] = streak_score

        # 5. Capability violation rate. An agent that has been
        #    triggering capability findings is structurally drifting.
        if baseline.capability_violation_rate > 0.0:
            cv_score = min(1.0, 1.5 * baseline.capability_violation_rate)
            if cv_score >= 0.30:
                findings.append(
                    Finding(
                        source="agent.behavioral",
                        rule_name="capability_violation_rate",
                        severity=Severity.WARNING,
                        message=(
                            f"Agent has a capability violation rate of "
                            f"{baseline.capability_violation_rate:.0%} over the last "
                            f"{baseline.sample_size} actions."
                        ),
                    )
                )
                reasons.append(
                    f"Capability violations occur in "
                    f"{baseline.capability_violation_rate:.0%} of recent actions."
                )
        else:
            cv_score = 0.0
        deviation_components["capability_violation_rate"] = cv_score

        # 6. Recent abstain rate.
        if recent_abstain_rate > 0.50:
            abstain_score = min(0.60, recent_abstain_rate * 0.80)
            uncertainty_flags.append("high_recent_abstain_rate")
            reasons.append(
                f"Agent abstain rate over the last {len(recent)} actions is "
                f"{recent_abstain_rate:.0%}; behavioral risk elevated."
            )
        else:
            abstain_score = 0.0
        deviation_components["recent_abstain_rate"] = abstain_score

        # 7. V11 — tenant-scope content novelty. This is the cross-agent
        #    signal that nobody else in the market evaluates: "no agent
        #    in your tenant has ever sent content like this before."
        tenant_novel_recipient = self._fold_tenant_signals(
            tenant_lookup=tenant_lookup,
            request=request,
            deviation_components=deviation_components,
            findings=findings,
            reasons=reasons,
            uncertainty_flags=uncertainty_flags,
        )

        # 8. Compose. We use a max-mean again — the mean catches steady
        #    drift, the max catches single-axis spikes.
        comp_values = [v for v in deviation_components.values() if v > 0.0] or [0.0]
        mean = sum(comp_values) / len(comp_values)
        max_v = max(comp_values)
        risk_score = min(1.0, 0.55 * mean + 0.45 * max_v)

        # 9. Confidence — proportional to sample size, capped.
        if baseline.sample_size >= _MIN_SAMPLE_FOR_FULL_CONFIDENCE:
            confidence = 0.85
        else:
            confidence = 0.50 + 0.014 * baseline.sample_size  # ramps to ~0.85 at 25
            uncertainty_flags.append("limited_behavioral_history")

        if novel_action:
            reasons.append(
                f"Action type {request.action_type!r} is novel for this agent."
            )
            uncertainty_flags.append("novel_action_for_agent")
        if novel_channel:
            reasons.append(
                f"Channel {request.channel!r} is novel for this agent."
            )
            uncertainty_flags.append("novel_channel_for_agent")
        if novel_recipient:
            reasons.append("Recipient domain is novel for this agent.")

        return BehavioralSignal(
            risk_score=round(risk_score, 4),
            confidence=round(min(1.0, confidence), 4),
            findings=tuple(findings),
            reasons=tuple(reasons),
            uncertainty_flags=tuple(uncertainty_flags),
            sample_size=baseline.sample_size,
            cold_start=False,
            novel_action_type=novel_action,
            novel_channel=novel_channel,
            novel_recipient_domain=novel_recipient,
            forbid_streak=baseline.forbid_streak,
            capability_violation_rate=baseline.capability_violation_rate,
            recent_abstain_rate=round(recent_abstain_rate, 4),
            deviation_components={
                k: round(v, 4) for k, v in deviation_components.items()
            },
            tenant_sample_size=tenant_lookup.sample_size,
            tenant_cold_start=tenant_lookup.cold_start,
            tenant_novelty_score=tenant_lookup.novelty_score,
            tenant_recipient_novel=tenant_novel_recipient,
        )

    # ------------------------------------------------------------------ tenant

    def _lookup_tenant(
        self,
        *,
        agent: AgentIdentity,
        request: EvaluationRequest,
    ) -> TenantContentBaselineLookup:
        """
        Compute the tenant-scope lookup, or return a neutral cold-start
        when no tenant baseline is wired. Centralized so both the
        cold-start path and the normal path share the same logic.
        """
        if self._tenant_baseline is None:
            return _neutral_tenant_lookup(agent.tenant_id)

        signature = compute_content_signature(request.content)
        return self._tenant_baseline.lookup(
            tenant_id=agent.tenant_id,
            action_type=request.action_type,
            signature=signature,
            recipient=request.recipient,
        )

    def _fold_tenant_signals(
        self,
        *,
        tenant_lookup: TenantContentBaselineLookup,
        request: EvaluationRequest,
        deviation_components: dict[str, float],
        findings: list[Finding],
        reasons: list[str],
        uncertainty_flags: list[str],
    ) -> bool:
        """
        Fold tenant-scope novelty into the existing behavioral signal.

        Returns the boolean tenant_novel_recipient flag. Mutates the
        passed-in collections in place — the calling evaluate() owns
        them. Two signals are folded:

          1. Tenant-novel content (Jaccard < threshold against the
             entire tenant baseline).
          2. Tenant-novel recipient domain (no agent in the tenant has
             ever sent to this domain on this action_type).
        """
        # Cold-start tenant: emit the uncertainty flag but never the
        # finding. We do not penalize agents in tenants that do not
        # yet have a baseline; that would punish day-one users.
        if tenant_lookup.cold_start:
            if tenant_lookup.sample_size == 0:
                uncertainty_flags.append("tenant_baseline_cold_start")
            else:
                uncertainty_flags.append("tenant_baseline_thin")
            deviation_components["tenant_novel_content"] = 0.0
            deviation_components["tenant_novel_recipient_domain"] = 0.0
            return False

        # Tenant-novel content. The deviation contribution scales with
        # how novel the content is. We use the raw novelty_score so it
        # is a smooth function of similarity rather than a step.
        novelty = tenant_lookup.novelty_score
        if novelty >= _TENANT_NOVEL_FINDING_THRESHOLD:
            deviation_components["tenant_novel_content"] = min(
                1.0, 0.40 + 0.6 * (novelty - _TENANT_NOVEL_FINDING_THRESHOLD)
                / max(0.01, 1.0 - _TENANT_NOVEL_FINDING_THRESHOLD)
            )
            findings.append(
                Finding(
                    source="agent.behavioral.tenant",
                    rule_name="tenant_novel_content",
                    severity=Severity.WARNING,
                    message=(
                        "Outbound content is unprecedented for this tenant on "
                        f"action_type {request.action_type!r}: novelty score "
                        f"{novelty:.2f} across {tenant_lookup.sample_size} prior "
                        "PERMITted signatures."
                    ),
                )
            )
            reasons.append(
                f"No agent in tenant has previously released content like this "
                f"on action_type {request.action_type!r} "
                f"(novelty {novelty:.2f}, similarity baseline "
                f"{tenant_lookup.sample_size})."
            )
            uncertainty_flags.append("tenant_novel_content")
        elif novelty >= _TENANT_NOVEL_UNCERTAINTY_THRESHOLD:
            # Soft deviation contribution; mark as uncertainty rather
            # than producing a finding. This is the "looks unusual but
            # we are not going to call it out" zone.
            deviation_components["tenant_novel_content"] = 0.20 + 0.30 * (
                novelty - _TENANT_NOVEL_UNCERTAINTY_THRESHOLD
            ) / max(0.01, _TENANT_NOVEL_FINDING_THRESHOLD - _TENANT_NOVEL_UNCERTAINTY_THRESHOLD)
            uncertainty_flags.append("tenant_content_unusual")
        else:
            deviation_components["tenant_novel_content"] = 0.0

        # Tenant-novel recipient domain. Only meaningful when the
        # request actually has a recipient with a parseable domain.
        tenant_novel_recipient = False
        if request.recipient and not tenant_lookup.recipient_domain_seen:
            # An unseen domain at tenant scope is a strictly stronger
            # signal than per-agent novelty alone.
            tenant_novel_recipient = True
            deviation_components["tenant_novel_recipient_domain"] = 0.50
            findings.append(
                Finding(
                    source="agent.behavioral.tenant",
                    rule_name="tenant_novel_recipient_domain",
                    severity=Severity.WARNING,
                    message=(
                        "Recipient domain is unseen tenant-wide for "
                        f"action_type {request.action_type!r}. No agent in this "
                        "tenant has previously sent here on this action."
                    ),
                )
            )
            reasons.append(
                f"Recipient domain is novel tenant-wide for action_type "
                f"{request.action_type!r}."
            )
            uncertainty_flags.append("tenant_novel_recipient_domain")
        else:
            deviation_components["tenant_novel_recipient_domain"] = 0.0

        return tenant_novel_recipient


def neutral_behavioral_signal() -> BehavioralSignal:
    """Neutral signal used when no agent is supplied."""
    return BehavioralSignal(
        risk_score=0.0,
        confidence=0.0,
        findings=tuple(),
        reasons=tuple(),
        uncertainty_flags=tuple(),
        sample_size=0,
        cold_start=False,
        novel_action_type=False,
        novel_channel=False,
        novel_recipient_domain=False,
        forbid_streak=0,
        capability_violation_rate=0.0,
        recent_abstain_rate=0.0,
        deviation_components={},
        tenant_sample_size=0,
        tenant_cold_start=True,
        tenant_novelty_score=0.0,
        tenant_recipient_novel=False,
    )


def _neutral_tenant_lookup(tenant_id: str) -> TenantContentBaselineLookup:
    """
    Tenant lookup used when no tenant baseline is wired in.

    Same shape as a real cold-start lookup. Lets the rest of the
    evaluator code path be unconditional.
    """
    normalized = tenant_id.strip().casefold() if tenant_id else "default"
    return TenantContentBaselineLookup(
        tenant_id=normalized or "default",
        sample_size=0,
        max_similarity=0.0,
        mean_similarity=0.0,
        novelty_score=0.0,
        recipient_domain_seen=False,
        recipient_domain_seen_count=0,
        cold_start=True,
    )


def _cold_start_signal(
    agent_id: UUID,
    recent_abstain_rate: float,
    tenant_lookup: TenantContentBaselineLookup,
) -> BehavioralSignal:
    """
    Signal returned when an agent has zero ledger entries.

    The tenant baseline can still inform a cold-start agent — that is
    in fact when it is most useful. We surface tenant_novelty_score
    and tenant_recipient_novel honestly, but we do NOT escalate the
    risk_score or emit findings on a cold-start agent. The router and
    fusion math already weigh cold-start agents conservatively; double
    counting the same uncertainty here would be miscalibrated.
    """
    uncertainty_flags = ["cold_start", "no_behavioral_history"]
    if tenant_lookup.cold_start:
        if tenant_lookup.sample_size == 0:
            uncertainty_flags.append("tenant_baseline_cold_start")
        else:
            uncertainty_flags.append("tenant_baseline_thin")

    tenant_novel_recipient = (
        not tenant_lookup.cold_start
        and not tenant_lookup.recipient_domain_seen
        and tenant_lookup.recipient_domain_seen_count == 0
        # the recipient_domain_seen flag captures the recipient case;
        # combined with cold_start guards above this only fires when
        # the tenant has data AND has not seen this recipient.
    )

    return BehavioralSignal(
        risk_score=0.20,  # mild positive — we don't know this agent yet
        confidence=0.40,
        findings=tuple(),
        reasons=("Agent has no behavioral history; cold-start signal returned.",),
        uncertainty_flags=tuple(uncertainty_flags),
        sample_size=0,
        cold_start=True,
        novel_action_type=True,
        novel_channel=True,
        novel_recipient_domain=True,
        forbid_streak=0,
        capability_violation_rate=0.0,
        recent_abstain_rate=round(recent_abstain_rate, 4),
        deviation_components={"cold_start": 0.20},
        tenant_sample_size=tenant_lookup.sample_size,
        tenant_cold_start=tenant_lookup.cold_start,
        tenant_novelty_score=tenant_lookup.novelty_score,
        tenant_recipient_novel=tenant_novel_recipient,
    )


def _domain_of(recipient: str) -> str | None:
    normalized = recipient.strip().casefold()
    if "@" in normalized:
        return normalized.rsplit("@", 1)[-1] or None
    if "://" in normalized:
        after = normalized.split("://", 1)[-1]
        host = after.split("/", 1)[0]
        return host or None
    return normalized or None
