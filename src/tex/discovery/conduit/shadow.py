"""
ShadowCorrelator — net-new cross-namespace correlation.

This is honestly net-new code. Reconciliation does NOT do this "for free": a
behavioral candidate keys ``external_id = resource_arn-or-principal`` under
``source=CLOUD_AUDIT``, structurally DISJOINT from a control-plane candidate's
``source=microsoft_graph`` / ``okta`` key — so two records for the same real
agent can never auto-collide in ``reconciliation_key``. Bridging the two planes
takes an explicit pass, and that pass is this module.

What it does, per tenant:

  * Build an index of control-plane principals by every deterministic identifier
    they expose (principal/app/client id, owner_hint).
  * For each behavioral actor, intersect ITS identifiers with that index. A
    non-empty intersection is a deterministic CORRELATION — the audit activity
    is attributed to the known control-plane agent and attached to it as
    evidence (NOT emitted as a second agent — no double counting).
  * An actor that intersects nothing **acted but appears in no control-plane
    scan** — a SHADOW agent. It is flagged with a confidence DIFFERENTIATED per
    provider: a Google token-audit shadow is less certain than an Entra one,
    because Google's audit retention is only ~180 days, so "absent from the
    control plane" is a weaker claim there.

Open question (per the kickoff): the default surfaces every unjoined actor as a
SHADOW candidate, but at the provider's confidence floor — so a low-certainty
Google shadow is visibly low-certainty rather than silently dropped or silently
trusted. The floor is configurable.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from tex.domain.discovery import CandidateAgent, DiscoverySource

SHADOW = "shadow"
CORRELATED = "correlated"

# Per-provider confidence floor for a SHADOW classification. Google/GCP lower
# because token-audit retention (~180 days) makes "never seen in the control
# plane" a weaker claim than it is for AWS CloudTrail or Entra sign-in logs.
DEFAULT_SHADOW_CONFIDENCE: dict[str, float] = {
    "google": 0.55,
    "google_workspace": 0.55,
    "gcp": 0.6,
    "aws": 0.85,
    "microsoft": 0.9,
    "okta": 0.9,
    "default": 0.8,
}


@dataclass(frozen=True, slots=True)
class ShadowFinding:
    """One behavioral actor's correlation verdict."""

    actor_handle: str  # the behavioral candidate's external_id
    classification: str  # SHADOW | CORRELATED
    behavioral_key: str  # reconciliation_key (CLOUD_AUDIT namespace)
    matched_control_plane_key: str | None
    join_basis: str | None  # the shared identifier that linked them
    provider: str
    confidence: float


@dataclass(frozen=True, slots=True)
class ShadowReport:
    findings: tuple[ShadowFinding, ...]

    @property
    def shadows(self) -> tuple[ShadowFinding, ...]:
        return tuple(f for f in self.findings if f.classification == SHADOW)

    @property
    def correlations(self) -> tuple[ShadowFinding, ...]:
        return tuple(f for f in self.findings if f.classification == CORRELATED)


def _default_control_keys(c: CandidateAgent) -> set[str]:
    keys = {c.external_id.casefold()}
    if c.owner_hint:
        keys.add(c.owner_hint.casefold())
    ev = c.evidence or {}
    for k in ("appId", "app_id", "clientId", "client_id", "objectId", "object_id", "spn"):
        v = ev.get(k)
        if v:
            keys.add(str(v).casefold())
    return {k for k in keys if k}


def _default_behavioral_keys(c: CandidateAgent) -> set[str]:
    keys = {c.external_id.casefold()}
    if c.owner_hint:
        keys.add(c.owner_hint.casefold())
    ev = c.evidence or {}
    arn = ev.get("resource_arn")
    if arn:
        keys.add(str(arn).casefold())
        tail = str(arn).rsplit("/", 1)[-1]
        if tail:
            keys.add(tail.casefold())
    for k in ("clientId", "client_id", "principalId", "principal_id", "appId", "app_id"):
        v = ev.get(k)
        if v:
            keys.add(str(v).casefold())
    return {k for k in keys if k}


def _default_provider_of(c: CandidateAgent) -> str:
    ev = c.evidence or {}
    return str(ev.get("log_vendor") or c.model_provider_hint or "unknown").casefold()


class ShadowCorrelator:
    def __init__(
        self,
        *,
        shadow_confidence: dict[str, float] | None = None,
        control_keys_of: Callable[[CandidateAgent], set[str]] = _default_control_keys,
        behavioral_keys_of: Callable[[CandidateAgent], set[str]] = _default_behavioral_keys,
        provider_of: Callable[[CandidateAgent], str] = _default_provider_of,
    ) -> None:
        self._shadow_confidence = dict(DEFAULT_SHADOW_CONFIDENCE)
        if shadow_confidence:
            self._shadow_confidence.update(shadow_confidence)
        self._control_keys = control_keys_of
        self._behavioral_keys = behavioral_keys_of
        self._provider_of = provider_of

    def _shadow_floor(self, provider: str) -> float:
        return self._shadow_confidence.get(provider, self._shadow_confidence["default"])

    def correlate(
        self,
        *,
        control_plane: list[CandidateAgent],
        behavioral: list[CandidateAgent],
    ) -> ShadowReport:
        # Index control-plane principals by every deterministic identifier.
        index: dict[str, str] = {}
        for c in control_plane:
            for key in self._control_keys(c):
                index.setdefault(key, c.reconciliation_key)

        findings: list[ShadowFinding] = []
        for b in behavioral:
            provider = self._provider_of(b)
            matched_key: str | None = None
            basis: str | None = None
            for key in sorted(self._behavioral_keys(b)):
                if key in index:
                    matched_key = index[key]
                    basis = key
                    break
            if matched_key is not None:
                findings.append(
                    ShadowFinding(
                        actor_handle=b.external_id,
                        classification=CORRELATED,
                        behavioral_key=b.reconciliation_key,
                        matched_control_plane_key=matched_key,
                        join_basis=basis,
                        provider=provider,
                        confidence=b.confidence,
                    )
                )
            else:
                findings.append(
                    ShadowFinding(
                        actor_handle=b.external_id,
                        classification=SHADOW,
                        behavioral_key=b.reconciliation_key,
                        matched_control_plane_key=None,
                        join_basis=None,
                        provider=provider,
                        confidence=self._shadow_floor(provider),
                    )
                )
        return ShadowReport(tuple(findings))

    # ------------------------------------------------------------------ apply
    def mark_shadows(
        self, behavioral: list[CandidateAgent], report: ShadowReport
    ) -> list[CandidateAgent]:
        """Return only the SHADOW behavioral candidates, each annotated with a
        ``shadow_finding`` evidence block, a ``shadow`` tag, and its
        per-provider confidence. Correlated actors are NOT returned here — they
        are absorbed into their control-plane principal (no double count)."""
        by_handle = {f.actor_handle: f for f in report.shadows}
        out: list[CandidateAgent] = []
        for b in behavioral:
            f = by_handle.get(b.external_id)
            if f is None:
                continue
            evidence = dict(b.evidence)
            evidence["shadow_finding"] = {
                "classification": SHADOW,
                "basis": "acted_but_unregistered",
                "provider": f.provider,
                "confidence": f.confidence,
            }
            out.append(
                b.model_copy(
                    update={
                        "evidence": evidence,
                        "confidence": f.confidence,
                        "tags": tuple(sorted({*b.tags, "shadow"})),
                    }
                )
            )
        return out

    def attach_correlations(
        self,
        control_plane: list[CandidateAgent],
        behavioral: list[CandidateAgent],
        report: ShadowReport,
    ) -> list[CandidateAgent]:
        """Return the control-plane candidates with correlated behavioral
        activity attached as evidence (the known agent was *seen acting*)."""
        beh_by_handle = {b.external_id: b for b in behavioral}
        # control-plane key -> list of correlated behavioral activity summaries
        by_cp: dict[str, list[dict]] = {}
        for f in report.correlations:
            b = beh_by_handle.get(f.actor_handle)
            if b is None:
                continue
            by_cp.setdefault(f.matched_control_plane_key, []).append(
                {
                    "actor_handle": f.actor_handle,
                    "join_basis": f.join_basis,
                    "operations": (b.evidence or {}).get("operations"),
                    "log_vendor": (b.evidence or {}).get("log_vendor"),
                }
            )
        out: list[CandidateAgent] = []
        for c in control_plane:
            corr = by_cp.get(c.reconciliation_key)
            if not corr:
                out.append(c)
                continue
            evidence = dict(c.evidence)
            evidence["correlated_behavioral_activity"] = corr
            out.append(c.model_copy(update={"evidence": evidence}))
        return out
