"""
PLANE-sealing seam — seal one ``SealedFact(PLANE)`` per observed plane snapshot.

This is the producer that turns the LIVE, in-memory ``PlaneSignalRegistry``
(``governance/plane_signals.py``) into a SEALED, offline-verifiable, point-in-time
fact the voice (``/v1/ask``) can answer from WITHOUT ever reading live state in
the answer path. The voice asks "is AtlasPay credential-enforced or decide-only?"
and reads the freshest sealed PLANE fact — or ABSTAINs. It never touches the live
registry, so the spoken answer rests on a tamper-evident snapshot, not a fresh
read whose basis can't be re-checked.

Why a DISTINCT kind (not ENFORCEMENT):
  * An ENFORCEMENT fact is a per-action gate event sealed with a PER-IDENTITY
    SEQUENCE NUMBER (``ledger.append_sequenced``); a MISSING ENFORCEMENT receipt
    is read as a BYPASS by ``ledger.verify_no_gaps``. A periodic plane snapshot is
    NOT a per-action gate event and has no action sequence — injecting it into that
    sequence would either corrupt gap-detection (false bypass holes) or force a
    faked ``claimed_seq``. So PLANE is appended with the PLAIN ``ledger.append`` and
    stays invisible to ``verify_no_gaps``.
  * A plane snapshot answers a DIFFERENT question ("what plane is this agent
    OBSERVED to be on right now") than ENFORCEMENT ("did the gate allow/block this
    one action"). Conflating them would make ``list_by_kind(ENFORCEMENT)`` a mix the
    voice would have to re-filter heuristically.

Honesty — what the seal proves and what it does NOT:
  * AUTHORSHIP + INTEGRITY of "agent X was OBSERVED on plane P at captured_at T":
    the ledger is SHA-256 hash-chained and ECDSA-P256 signed. It does NOT prove the
    plane is "correct", and it NEVER asserts authorization — the claim string says
    "observed signal, NOT asserted from capability; possession != authorization" and
    carries ``last_handshake_ts`` + ``captured_at`` so the answer is
    freshness-checkable. A sealed ``DECIDE-ONLY`` means "no fresh upgrade signal
    observed at snapshot time", NOT "proven not-enforced". Maturity is
    ``RESEARCH_SOLID`` (real, live crypto; a newly-wired governance fact).

Fail-closed, observation-only (mirrors ``decision_seal.seal_decision`` exactly):
  * ``ledger is None`` -> zero-cost no-op, returns ``None`` (the prod-INERT default).
  * an append failure is logged and returns ``None`` — it never raises into the
    snapshotter and never changes any agent's actual plane (this seam OBSERVES, it
    does not enforce: a sealed PLANE fact stops nothing and upgrades nothing).
"""

from __future__ import annotations

import logging
import time

from tex.domain.evidence import EvidenceMaturity
from tex.provenance.ledger import SealedFactLedger
from tex.provenance.models import SealedFact, SealedFactKind, SealedFactRecord

# Sentinel for "no value observed" that is distinct from a real ``None``
# last_handshake_ts (the honest DECIDE-ONLY floor) — so "no prior fact" is never
# confused with "a prior fact whose handshake was None".
_MISSING = object()

_logger = logging.getLogger(__name__)

# Real, live ECDSA-P256 + hash-chain crypto (authorship + integrity), newly wired
# as a governance fact and not externally anchored — the same honesty convention
# the DECISION/ENFORCEMENT/ATTEMPT seals use.
_PLANE_MATURITY = EvidenceMaturity.RESEARCH_SOLID


def build_plane_fact(
    agent_id: str,
    plane: str,
    *,
    tenant: str,
    last_handshake_ts: float | None,
    captured_at: float,
    agent_name: str | None = None,
) -> SealedFact:
    """Map one observed plane snapshot to a canonical ``SealedFact(PLANE)``.

    Pure (no I/O, no mutation). The ``claim`` is deliberately narrow: it asserts
    only that the agent was OBSERVED on ``plane`` at ``captured_at`` (carrying both
    timestamps so the answer is freshness-checkable) and explicitly disclaims
    capability/authorization — never that the agent IS enforced or authorized.

    ``plane`` must be EXACTLY the value ``PlaneSignalRegistry.derive(...)`` returned
    for this agent (we seal the observed signal byte-for-byte, never an upgraded
    guess). On a default/empty registry that is ``DECIDE-ONLY`` with
    ``last_handshake_ts=None`` — the honest floor.
    """
    claim = (
        f"agent {agent_id} is observed on enforcement plane {plane} "
        f"(as of captured_at={captured_at}; last_handshake_ts={last_handshake_ts}) "
        f"— observed signal, NOT asserted from capability; possession != authorization"
    )
    detail = {
        "agent_id": agent_id,
        "agent_name": agent_name,
        "plane": plane,
        "last_handshake_ts": last_handshake_ts,
        "tenant": tenant,
        "captured_at": captured_at,
    }
    return SealedFact(
        kind=SealedFactKind.PLANE,
        subject_id=agent_id,
        claim=claim,
        maturity=_PLANE_MATURITY,
        detail=detail,
    )


def seal_plane(
    ledger: SealedFactLedger | None,
    agent_id: str,
    plane: str,
    *,
    tenant: str,
    last_handshake_ts: float | None,
    captured_at: float | None = None,
    agent_name: str | None = None,
) -> SealedFactRecord | None:
    """Seal one ``PLANE`` fact into ``ledger`` and return its record.

    Uses the PLAIN ``ledger.append`` (NOT ``append_sequenced``) on purpose — a
    plane snapshot is not a per-action gate event, so it must stay out of the
    per-identity sequence ``verify_no_gaps`` reads (a missing snapshot is not a
    bypass).

    Fail-closed and observation-only, mirroring ``seal_decision``:
      * ``ledger is None`` -> no-op, return ``None`` (the prod-INERT default).
      * an append failure is logged and returns ``None`` — it never propagates
        into the snapshotter and never changes any agent's plane.
    """
    if ledger is None:
        return None
    try:
        return ledger.append(
            build_plane_fact(
                agent_id,
                plane,
                tenant=tenant,
                last_handshake_ts=last_handshake_ts,
                captured_at=time.time() if captured_at is None else float(captured_at),
                agent_name=agent_name,
            )
        )
    except Exception:  # pragma: no cover - defensive; a seal must never break the snapshotter
        _logger.warning(
            "PLANE seal failed for agent %s; plane unaffected, fact not sealed",
            agent_id,
            exc_info=True,
        )
        return None


def snapshot_planes(
    ledger: SealedFactLedger | None,
    governance: object,
    registry: object,
    *,
    tenant: str,
    captured_at: float | None = None,
) -> int:
    """Seal one PLANE fact per governed agent in ``tenant`` from the LIVE registry.

    This is the producer's one tick: it walks exactly the same governed-agent
    enumeration the ``GET /v1/govern/agents/plane`` endpoint uses
    (``governance._list_tenant_agents`` + ``_is_governable`` + ``_agent_uuid``) and
    seals what ``registry.derive(agent_id, tenant)`` returned for each — the honest
    observed signal, DECIDE-ONLY by default. Returns the count sealed (0 on a
    ``ledger is None`` no-op, so a default boot does nothing here).

    Reading the live registry happens HERE, in the producer — never in the voice
    answer path. The answer path only ever reads SEALED PLANE facts.
    """
    if ledger is None:
        return 0
    when = time.time() if captured_at is None else float(captured_at)
    sealed = 0
    try:
        agents = governance._list_tenant_agents(tenant)  # noqa: SLF001 — same accessor the endpoint uses
    except Exception:  # noqa: BLE001 — never break the snapshotter on a registry hiccup
        return 0
    for agent in agents:
        try:
            if not governance._is_governable(agent):  # noqa: SLF001
                continue
            uid = governance._agent_uuid(agent)  # noqa: SLF001
            agent_name = (
                getattr(agent, "external_agent_id", None)
                or getattr(agent, "name", None)
                or None
            )
            agent_id = str(uid) if uid is not None else str(agent_name or "")
            if not agent_id:
                continue
            derived = registry.derive(agent_id, tenant)
            rec = seal_plane(
                ledger,
                agent_id,
                derived.plane,
                tenant=tenant,
                last_handshake_ts=derived.last_handshake_ts,
                captured_at=when,
                agent_name=str(agent_name) if agent_name is not None else None,
            )
            if rec is not None:
                sealed += 1
        except Exception:  # noqa: BLE001 — one bad agent must not abort the whole tick
            _logger.warning("PLANE snapshot skipped one agent", exc_info=True)
            continue
    return sealed


def _latest_sealed_plane(
    ledger: SealedFactLedger,
    agent_id: str,
    tenant: str,
) -> tuple[str, object] | None:
    """Read the most-recent sealed PLANE fact for ``(agent_id, tenant)`` and
    return ``(plane, last_handshake_ts)`` — or ``None`` if none exists.

    "Most-recent" is the freshest ``captured_at`` (ties broken by seal order, the
    later record winning), EXACTLY the selection the voice answer path uses
    (``/v1/ask`` plane branch picks the max-``captured_at`` snapshot). This is the
    single source of truth the change-check compares against, so a seal-on-change
    tick never disagrees with what the voice would currently answer.

    Read-only — never mutates the ledger; a registry/ledger hiccup degrades to
    ``None`` (treated as "no prior fact" → the next tick seals once, then settles).
    """
    best_when = None
    best: tuple[str, object] | None = None
    try:
        records = ledger.list_by_kind(SealedFactKind.PLANE)
    except Exception:  # noqa: BLE001 — defensive; never break the snapshotter
        return None
    for idx, rec in enumerate(records):
        detail = getattr(rec.fact, "detail", None) or {}
        if rec.fact.subject_id != agent_id:
            continue
        if (detail.get("tenant") or None) != (tenant or None):
            continue
        when = detail.get("captured_at")
        when_key = (float(when) if when is not None else float("-inf"), idx)
        if best_when is None or when_key > best_when:
            best_when = when_key
            best = (detail.get("plane"), detail.get("last_handshake_ts", _MISSING))
    return best


def snapshot_planes_on_change(
    ledger: SealedFactLedger | None,
    governance: object,
    registry: object,
    *,
    tenant: str,
    captured_at: float | None = None,
) -> int:
    """Seal a fresh PLANE fact ONLY for agents whose derived plane CHANGED.

    This is the BOUNDED, continuous variant of :func:`snapshot_planes`. It walks
    the same governed-agent enumeration and reads the same
    ``registry.derive(agent_id, tenant)`` observed signal, but before sealing it
    compares that signal against the agent's MOST-RECENT sealed PLANE fact
    (:func:`_latest_sealed_plane`) and seals ONLY when:

      * no prior sealed PLANE fact exists for this agent (first observation), OR
      * the derived ``plane`` differs from the last sealed plane, OR
      * the derived ``last_handshake_ts`` differs (a freshness change at the same
        plane — e.g. a re-handshake — still a real observed delta worth sealing).

    Why this keeps the ledger BOUNDED: in a steady-state estate (every agent
    DECIDE-ONLY and unchanging) each agent seals exactly once — the very first
    tick that sees it — and every subsequent tick seals NOTHING. So per-tick
    growth in steady state is ZERO; the ledger grows only on a genuine plane
    transition. This is what makes "re-snapshot every standing cycle forever" safe.

    The sealed claim still EQUALS the observed ``derive()`` output byte-for-byte
    (it reuses :func:`seal_plane` / :func:`build_plane_fact`, no upgraded guess,
    same possession != authorization disclaimer). Returns the count NEWLY sealed
    (0 on a ``ledger is None`` no-op, so a default boot does nothing here).
    """
    if ledger is None:
        return 0
    when = time.time() if captured_at is None else float(captured_at)
    sealed = 0
    try:
        agents = governance._list_tenant_agents(tenant)  # noqa: SLF001 — same accessor the endpoint uses
    except Exception:  # noqa: BLE001 — never break the snapshotter on a registry hiccup
        return 0
    for agent in agents:
        try:
            if not governance._is_governable(agent):  # noqa: SLF001
                continue
            uid = governance._agent_uuid(agent)  # noqa: SLF001
            agent_name = (
                getattr(agent, "external_agent_id", None)
                or getattr(agent, "name", None)
                or None
            )
            agent_id = str(uid) if uid is not None else str(agent_name or "")
            if not agent_id:
                continue
            derived = registry.derive(agent_id, tenant)
            prior = _latest_sealed_plane(ledger, agent_id, tenant)
            if prior is not None:
                prior_plane, prior_handshake = prior
                # Bounded: an UNCHANGED plane seals nothing. We compare both the
                # plane and the handshake freshness so the steady state (identical
                # observed signal) is a true no-op, but a real re-handshake/upgrade
                # at the same plane still seals a fresh, freshness-checkable fact.
                if (
                    prior_plane == derived.plane
                    and prior_handshake is not _MISSING
                    and prior_handshake == derived.last_handshake_ts
                ):
                    continue
            rec = seal_plane(
                ledger,
                agent_id,
                derived.plane,
                tenant=tenant,
                last_handshake_ts=derived.last_handshake_ts,
                captured_at=when,
                agent_name=str(agent_name) if agent_name is not None else None,
            )
            if rec is not None:
                sealed += 1
        except Exception:  # noqa: BLE001 — one bad agent must not abort the whole tick
            _logger.warning("PLANE seal-on-change skipped one agent", exc_info=True)
            continue
    return sealed
