"""
SIEVE coverage summary — turn a multi-plane ``PlanesResult`` into the honest,
spoken coverage clause + a structured object handle (ARCHITECTURE.md §9).

The headline is NEVER a bare count and NEVER an implied totality. It is: how many
agents were resolved, which planes actually saw them, and how many are still
dark — after which the spoken line yields to Begin. The vantage that would open
each blind plane still rides in the structured object as "needs vantage X", never
as zero/absent — the honesty doctrine the whole layer exists to keep.

``summarize`` NEVER raises: every field is read defensively so it can run inside
the ignite path without ever breaking Begin.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from tex.discovery.engine.models import PlaneId

#: plane -> (spoken name, the vantage that would light it up). Used both for the
#: planes that fired (name) and the planes still blind (name + how to open them).
_PLANE: dict[PlaneId, tuple[str, str]] = {
    PlaneId.ACTIONS_TRAIL: ("activity logs", "an activity-log source"),
    PlaneId.FS_WRITE: ("file writes", "a workspace to scan"),
    PlaneId.NETWORK_EGRESS: ("network egress", "a flow tap or AI-gateway feed"),
    PlaneId.KERNEL_EBPF: ("the kernel", "a host eBPF sensor"),
    PlaneId.ENDPOINT_EDR: ("endpoints", "endpoint telemetry"),
    PlaneId.SIGNED_ID: ("the identity directory", "directory credentials"),
    PlaneId.MANAGED_CONTROL: ("managed agent platforms", "cloud-audit access"),
    PlaneId.SAAS_AUTOMATION: ("SaaS and automations", "a SaaS token"),
    PlaneId.GOVERNANCE_STREAM: ("the governance stream", "agents calling the gate"),
    PlaneId.STATIC_SUPPLYCHAIN: ("code and manifests", "a repository to scan"),
    PlaneId.MCP_TOOLGRAPH: ("the MCP tool-graph", "MCP server endpoints"),
    PlaneId.HONEYTOKEN: ("decoys", "a planted honeytoken"),
}

#: Meta / synthetic planes that are not real vantages to speak about.
_META = frozenset({PlaneId.WITHHELD_THIRD, PlaneId.COVERAGE_HEALTH})


@dataclass(frozen=True)
class Coverage:
    """Structured coverage handle for one ignite (the object behind the spoken)."""

    count: int = 0
    fired: tuple[str, ...] = ()
    blind: tuple[dict[str, str], ...] = ()  # [{"plane": name, "needs": vantage}]
    unseen_lower: float | None = None
    unseen_ci: tuple[float, float] | None = None
    health: str | None = None
    clause: str = ""  # the honest sentence spoken after the count

    def as_object(self) -> dict[str, Any]:
        return {
            "count": self.count,
            "fired": list(self.fired),
            "blind": [dict(b) for b in self.blind],
            "unseen_lower": self.unseen_lower,
            "unseen_ci": list(self.unseen_ci) if self.unseen_ci else None,
            "coverage_health": self.health,
        }


def _join(names: list[str]) -> str:
    if not names:
        return ""
    if len(names) == 1:
        return names[0]
    if len(names) == 2:
        return f"{names[0]} and {names[1]}"
    return f"{', '.join(names[:-1])}, and {names[-1]}"


#: Spell small counts so the spoken line is consistent with the humanized agent
#: count (the blind-plane count is always <= the roster size).
_NUM_WORDS = (
    "zero", "one", "two", "three", "four", "five", "six", "seven",
    "eight", "nine", "ten", "eleven", "twelve", "thirteen", "fourteen",
)


def _words(n: int) -> str:
    return _NUM_WORDS[n] if 0 <= n < len(_NUM_WORDS) else str(n)


def summarize(result: Any, headline_count: int | None = None) -> Coverage:
    """Map a ``PlanesResult`` to the honest coverage handle + spoken clause.

    ``headline_count`` is the count the surface actually speaks (e.g. a connected
    directory's agents, which arrive via the legacy path, not a SIEVE plane). When
    given, the clause stays COHERENT with it — it never says "nothing surfaced"
    while the headline is non-zero; it enumerates the planes still dark instead.
    """
    entities = tuple(getattr(result, "entities", ()) or ())
    count = len(entities)
    occasions = set(getattr(result, "occasions", ()) or ())
    active = [p for p in (getattr(result, "active_planes", ()) or ()) if p not in _META]

    fired_planes = [p for p in active if p in occasions]
    blind_planes = [p for p in active if p not in occasions]

    fired = tuple(_PLANE.get(p, (p.value, ""))[0] for p in fired_planes)
    blind = tuple(
        {"plane": _PLANE.get(p, (p.value, ""))[0], "needs": _PLANE.get(p, ("", "a source"))[1]}
        for p in blind_planes
    )

    unseen = getattr(result, "unseen", None)
    lower = getattr(unseen, "lower", None)
    ci = None
    if unseen is not None:
        lo, hi = getattr(unseen, "ci_low", None), getattr(unseen, "ci_high", None)
        if lo is not None and hi is not None:
            ci = (float(lo), float(hi))
    health = getattr(unseen, "coverage_health", None)

    # The spoken clause — actionable honesty, never a totality claim. Enumerate
    # where agents were found (if any plane fired) and the planes still dark + the
    # vantage that would open the biggest one. Stays coherent with the headline.
    effective = headline_count if headline_count is not None else count
    parts: list[str] = []
    if fired:
        parts.append(f"I found them across {_join(list(fired))}")
    if blind_planes:
        n = len(blind_planes)
        subj = f"{_words(n)} planes are" if n != 1 else "one plane is"
        parts.append(f"{subj} still dark — I'll begin")
    if parts:
        clause = ". ".join(p[0].upper() + p[1:] for p in parts) + "."
    elif effective > 0:
        clause = ""  # the headline already speaks the count; nothing honest to add
    else:
        clause = "Nothing has surfaced yet on the planes I can see."

    return Coverage(
        count=count,
        fired=fired,
        blind=blind,
        unseen_lower=float(lower) if lower is not None else None,
        unseen_ci=ci,
        health=health,
        clause=clause,
    )


__all__ = ["Coverage", "summarize"]
