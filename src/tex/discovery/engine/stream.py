"""
SIEVE STREAM — the incremental/online resolver (ARCHITECTURE.md §5).

``pipeline.run_slice`` / ``run_planes`` are BATCH: they accumulate a whole
window of incidences, then run FUSE → ESTIMATE → ADAPT once. This module adds
the CONTINUOUS path WITHOUT touching that batch envelope: a long-lived
``StreamingResolver`` that ingests ``Incidence`` events one-by-one (or in small
batches) and, for each update, re-resolves ONLY the touched graph components —
never a full re-walk of the estate.

The five §5 commitments, each realized here:

1. **Incremental resolution / bounded re-resolution.** ``feed`` blocks the new
   incidence against an inverted blocking index (the same union-of-blockers
   keys ``fuse._block`` uses), collects the SMALL set of candidate-neighbour
   incidences, unions in their current entities' members, and re-runs the full
   resolution brain (``pipeline.resolve_full``) over ONLY that touched subgraph.
   Untouched components are never re-scored. Cost is bounded by touched-component
   size, not by total estate size — the benchmark target.

2. **tighten()-only confidence.** A provisional entity is emitted on its FIRST
   instant-plane sighting; on every later corroboration its confidence is
   monotonically TIGHTENED (never loosened) — a per-identity confidence FLOOR is
   carried across re-resolutions and re-applied via ``SieveEntity.tighten`` so a
   re-cluster can only raise an entity's confidence.

3. **Online completeness.** The capture-recapture unseen estimate
   (``estimate.estimate_unseen``) is recomputed over the whole live entity set
   each window and the window-over-window DELTA in the unseen fraction and
   coverage health is reported (online re-estimate; cheap, O(entities)).

4. **Disappearance via PresenceTracker.** Each ``window`` call drives
   ``PresenceTracker.observe_window``: live identity keys → ``observe_seen``,
   previously-known-but-absent keys → ``observe_missing``; the
   N-consecutive-miss threshold yields false-positive-suppressed
   ``confirmed_disappeared``.

5. **Capability drift.** Drift events are surfaced from
   ``capability.map_capability``'s per-entity ``drift`` tuple as the window's
   ``capability_drift``.

Everything is import-safe and default-safe: constructing a ``StreamingResolver``
never touches the network or a DB (the ``PresenceTracker`` degrades to in-memory
when ``DATABASE_URL`` is unset), and nothing here runs unless a caller invokes
it — the live wiring stays gated behind ``TEX_SIEVE_ENABLED`` exactly as the
batch path is (ARCHITECTURE.md §8).
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Iterable, Sequence
from uuid import UUID

from tex.discovery.engine.estimate import estimate_unseen
from tex.discovery.engine.models import Incidence, PlaneId, SieveEntity
from tex.discovery.engine.pipeline import resolve_full
from tex.discovery.presence import PresenceTracker, WindowPresenceDelta

#: The INSTANT planes (ARCHITECTURE.md §5): a sighting on any of these emits a
#: provisional entity immediately, before fast/slow planes corroborate. The
#: slice's two real planes are instant (they ARE the first sighting); the roster
#: instant vantages are the eBPF/identity/network ground-truth planes.
INSTANT_PLANES: frozenset[PlaneId] = frozenset(
    {
        PlaneId.ACTIONS_TRAIL,
        PlaneId.FS_WRITE,
        PlaneId.KERNEL_EBPF,
        PlaneId.SIGNED_ID,
        PlaneId.NETWORK_EGRESS,
        PlaneId.ENDPOINT_EDR,
    }
)


def _stable_key(entity: SieveEntity) -> str:
    """The cross-window stable identity key for an entity.

    Mirrors ``fuse._stamp_axes_and_label`` / the output-boundary
    ``reconciliation_key`` doctrine (ARCHITECTURE.md §1.3): ``merge_axis`` is the
    stable agent identifier the component is stitched on (external id → code-hash
    → workspace path), so it survives credential rotation and re-clustering. We
    fall back to the synthetic ``entity_id`` only when no merge axis exists yet
    (a singleton with no merge-grade key) — that entity is still tracked, just
    keyed on its stable UUID until a merge axis appears.
    """
    return entity.merge_axis or str(entity.entity_id)


@dataclass(frozen=True)
class StreamDelta:
    """The per-window delta the streaming resolver emits (ARCHITECTURE.md §5).

    Shape (locked by §5): ``{ new_entities[], tightened[], confirmed_disappeared[],
    capability_drift[], unseen_fraction_delta, coverage_health_delta }``.

    - ``new_entities``          — stable keys first seen this window (a provisional
                                  entity on first instant-plane sighting).
    - ``tightened``             — ``(stable_key, old_conf, new_conf)`` for every
                                  entity whose confidence MONOTONICALLY rose this
                                  window (never an entry where new < old).
    - ``confirmed_disappeared`` — stable keys that crossed the N-consecutive-miss
                                  threshold this window (false-positive-suppressed).
    - ``capability_drift``      — ``(stable_key, token)`` for each capability token
                                  whose grade/presence mutated this window.
    - ``unseen_fraction_delta`` — change in the unseen-fraction lower bound vs the
                                  previous window (online capture-recapture update).
    - ``coverage_health_delta`` — ``(old_health, new_health)`` when the coverage
                                  health word changed, else ``None``.
    - ``touched_components``    — how many existing components the update touched
                                  (the re-resolution work bound); ``occasions`` =
                                  the live capture occasions this window. Receipts.
    """

    new_entities: tuple[str, ...] = ()
    tightened: tuple[tuple[str, float, float], ...] = ()
    confirmed_disappeared: tuple[str, ...] = ()
    capability_drift: tuple[tuple[str, str], ...] = ()
    unseen_fraction_delta: float = 0.0
    coverage_health_delta: tuple[str, str] | None = None
    touched_components: int = 0
    occasions: tuple[PlaneId, ...] = ()


@dataclass
class _Tracked:
    """The live per-identity state the resolver carries across windows."""

    entity: SieveEntity
    confidence_floor: float = 0.0
    capability_tokens: frozenset[str] = frozenset()


class StreamingResolver:
    """Incremental SIEVE resolver — online, bounded-re-resolution, tighten-only.

    Holds the live entity graph as a set of resolved ``SieveEntity`` keyed by a
    stable identity key (``merge_axis``). ``feed`` / ``feed_batch`` ingest new
    incidences and re-resolve ONLY the touched components, returning the
    ``StreamDelta`` for that update. ``window`` closes a scan window: it drives
    the ``PresenceTracker`` disappearance machine over the keys live since the
    last window and folds the confirmed-disappeared signal + the online
    unseen-fraction re-estimate into the delta.

    Construction is side-effect-free and default-safe (no network / no DB unless
    ``DATABASE_URL`` is set, in which case the tracker persists — same posture as
    the batch path).
    """

    def __init__(
        self,
        *,
        tenant_id: str = "default",
        occasions: Sequence[PlaneId] = (PlaneId.ACTIONS_TRAIL, PlaneId.FS_WRITE),
        withheld_planes: Sequence[PlaneId] = (PlaneId.WITHHELD_THIRD,),
        presence: PresenceTracker | None = None,
        missing_threshold: int = 3,
        registry=None,  # noqa: ANN001 - InMemoryAgentRegistry (optional sink)
        ledger=None,  # noqa: ANN001 - InMemoryDiscoveryLedger (optional sink)
        index=None,  # noqa: ANN001 - ReconciliationIndex (optional; built if needed)
    ) -> None:
        self._tenant_id = tenant_id
        self._occasions = tuple(occasions)
        self._withheld = tuple(dict.fromkeys(withheld_planes))
        self._presence = presence or PresenceTracker(missing_threshold=missing_threshold)

        # OUTPUT ADAPTER sink (optional). When a registry + ledger are supplied,
        # every entity that is NEW or TIGHTENED this delta is projected through
        # ``adapter.project`` (registry.save → ledger.append) — registry-first /
        # ledger-last, exactly like the batch path (ARCHITECTURE.md §7). The
        # index defaults to a fresh ``ReconciliationIndex`` bootstrapped from the
        # registry so a tightened entity re-links to its SAME agent_id across
        # windows instead of churning a duplicate. A None registry/ledger keeps
        # the resolver a pure in-memory delta engine (the default-safe posture).
        self._registry = registry
        self._ledger = ledger
        self._index = index
        if registry is not None and ledger is not None and index is None:
            from tex.discovery.service import ReconciliationIndex

            self._index = ReconciliationIndex(registry=registry)

        # Live state.
        self._tracked: dict[str, _Tracked] = {}
        self._inc_by_id: dict[UUID, Incidence] = {}
        # incidence_id -> stable key it currently belongs to.
        self._key_of_inc: dict[UUID, str] = {}
        # (blocking key name, value) -> set of incidence_ids carrying it.
        self._block_index: dict[tuple[str, str], set[UUID]] = defaultdict(set)
        # keys seen at least once since the last window() close.
        self._seen_this_window: set[str] = set()

        # Online completeness memo (previous window's headline) for the delta.
        self._prev_unseen_lower: float | None = None
        self._prev_health: str | None = None

        # Receipt: how many times an entity was projected through the adapter
        # (registry.save → ledger.append). Each new/tightened entity in a touched
        # subgraph counts one projection — proof the streaming path drives the
        # governance boundary, not just an in-memory graph.
        self._projected_total = 0

    # ------------------------------------------------------------------ reads

    @property
    def entities(self) -> tuple[SieveEntity, ...]:
        """The current live entity set (object handle; never a forced table)."""
        return tuple(t.entity for t in self._tracked.values())

    @property
    def estate_size(self) -> int:
        """Number of distinct live entities (the background the bound is vs.)."""
        return len(self._tracked)

    @property
    def projected_total(self) -> int:
        """Total adapter projections (registry.save → ledger.append) so far.

        Zero when no sink is wired. Proof the streaming path lands entities
        through the governance boundary, not just an in-memory graph.
        """
        return self._projected_total

    @property
    def has_sink(self) -> bool:
        """Whether an output-adapter sink (registry + ledger) is wired."""
        return self._registry is not None and self._ledger is not None

    def confidence_of(self, stable_key: str) -> float | None:
        """The current monotone confidence floor for a tracked identity."""
        t = self._tracked.get(stable_key)
        return t.confidence_floor if t is not None else None

    # ------------------------------------------------------------------ ingest

    def feed_batch(self, incidences: Iterable[Incidence]) -> StreamDelta:
        """Ingest a small batch of incidences, re-resolving only touched parts.

        Equivalent to feeding each incidence then merging the deltas, but the
        whole batch shares ONE bounded re-resolution pass so a burst of
        co-arriving sightings of the same agent does not re-cluster repeatedly.
        """
        incs = [inc for inc in incidences if inc is not None]
        if not incs:
            return self._empty_delta()
        return self._ingest(incs)

    def feed(self, incidence: Incidence) -> StreamDelta:
        """Ingest ONE incidence and return the delta for that update.

        Blocks the incidence against the live index to find candidate neighbours,
        unions in the entities those neighbours currently belong to (the TOUCHED
        components), and re-resolves only that subgraph. No full estate re-walk.
        """
        if incidence is None:
            return self._empty_delta()
        return self._ingest([incidence])

    def _ingest(self, incs: list[Incidence]) -> StreamDelta:
        # 1. Find the touched components: every existing entity that shares a
        #    blocking key with one of the new incidences. This is the ONLY place
        #    the estate is consulted, and it is consulted through the inverted
        #    index — O(new-incidence keys + neighbour incidences), not O(estate).
        touched_keys: set[str] = set()
        for inc in incs:
            for kname, kval in inc.footprint.keys:
                for nbr_id in self._block_index.get((kname, kval), ()):
                    nbr_key = self._key_of_inc.get(nbr_id)
                    if nbr_key is not None:
                        touched_keys.add(nbr_key)

        # 2. Assemble the subgraph incidence pool: the new incidences + every
        #    member incidence of the touched components. Untouched entities are
        #    NOT included — they are not re-scored.
        pool: dict[UUID, Incidence] = {inc.incidence_id: inc for inc in incs}
        for tkey in touched_keys:
            for mid in self._tracked[tkey].entity.incidences:
                src = self._inc_by_id.get(mid)
                if src is not None:
                    pool[mid] = src

        # 3. Re-resolve ONLY the subgraph (full brain: FUSE + disambiguate +
        #    capability), bounded by touched-component size.
        resolved = resolve_full(tuple(pool.values()))

        # 4. SNAPSHOT the touched components' prior state BEFORE retiring them, so
        #    a re-resolved entity that maps back to an existing identity is scored
        #    as a TIGHTEN (not a spurious "new"). The snapshot also carries the
        #    stable entity_id and the prior capability tokens forward.
        prior: dict[str, _Tracked] = {
            tkey: self._tracked[tkey] for tkey in touched_keys
        }

        # Retire the touched components, register the new incidences, and fold
        # the re-resolved entities back in with tighten-only confidence.
        for tkey in touched_keys:
            self._retire(tkey)
        for inc in incs:
            self._register_incidence(inc)

        new_keys: list[str] = []
        tightened: list[tuple[str, float, float]] = []
        drift: list[tuple[str, str]] = []

        for entity in resolved:
            key = _stable_key(entity)
            existing = prior.get(key)
            old_floor = existing.confidence_floor if existing else 0.0

            # tighten-only: the new confidence may only RAISE the carried floor.
            entity.tighten(old_floor)
            new_floor = entity.fusion_confidence

            # Carry the stable entity_id forward so identity is continuous.
            if existing is not None:
                entity.entity_id = existing.entity.entity_id

            tokens = self._tokens_of(entity)
            if existing is None:
                new_keys.append(key)
            elif new_floor > old_floor:
                tightened.append((key, old_floor, new_floor))

            # Capability drift: tokens the entity's own graph flagged as mutated,
            # plus tokens that newly appeared vs the last time we saw this entity.
            graph = entity.capability_graph
            if graph is not None:
                for tok in graph.drift:
                    drift.append((key, tok))
            if existing is not None:
                for tok in sorted(tokens - existing.capability_tokens):
                    drift.append((key, tok))

            self._tracked[key] = _Tracked(
                entity=entity,
                confidence_floor=new_floor,
                capability_tokens=tokens,
            )
            self._seen_this_window.add(key)
            # Re-key this entity's member incidences to the stable key.
            for mid in entity.incidences:
                self._key_of_inc[mid] = key

            # OUTPUT ADAPTER (§7): land this re-resolved entity through the
            # governance boundary so ``StandingGovernance.decide`` can govern it.
            # Every entity in the touched subgraph is (re)projected: a NEW entity
            # registers + appends; a KNOWN entity re-links to its existing
            # agent_id (no duplicate) and appends a fresh hash-chained ledger row.
            # Bounded by touched-component size — never a full-estate re-write.
            self._project(entity)

        return StreamDelta(
            new_entities=tuple(new_keys),
            tightened=tuple(tightened),
            capability_drift=tuple(dict.fromkeys(drift)),
            touched_components=len(touched_keys),
            occasions=self._live_occasions(),
        )

    def _project(self, entity: SieveEntity) -> None:
        """Drive the output adapter for one entity when a sink is wired.

        No-op when no registry/ledger sink was supplied (the pure delta-engine
        posture). Never raises: the adapter honors a gate-blocked save as a
        silent no-op, and an unexpected sink error must not break the stream, so
        a projection failure is swallowed (the delta is still emitted) — the same
        fail-soft posture the batch sensors take.
        """
        if self._registry is None or self._ledger is None:
            return
        from tex.discovery.engine import adapter

        try:
            adapter.project(entity, self._registry, self._ledger, self._index)
            self._projected_total += 1
        except Exception:  # noqa: BLE001 - a sink failure must not break the stream
            pass

    # ------------------------------------------------------------------ window

    def window(self) -> StreamDelta:
        """Close a scan window: presence delta + online unseen re-estimate.

        Drives the ``PresenceTracker`` over the keys seen since the previous
        ``window`` (live → ``observe_seen``, previously-known-but-absent →
        ``observe_missing``); the N-consecutive-miss threshold yields
        false-positive-suppressed ``confirmed_disappeared``. Then recomputes the
        capture-recapture unseen estimate over the live entity set and reports the
        window-over-window deltas in the unseen fraction and coverage health.

        Resets the per-window seen set so the NEXT window's missing detection is
        relative to this close. Returns a ``StreamDelta`` carrying only the
        window-close fields populated (no new/tightened — those come from
        ``feed``).
        """
        seen = set(self._seen_this_window)
        known = set(self._tracked.keys())
        presence_delta: WindowPresenceDelta = self._presence.observe_window(
            tenant_id=self._tenant_id,
            seen_keys=seen,
            known_keys=known,
            discovery_source="sieve_stream",
        )

        # Online completeness: recompute the unseen fraction over the live set.
        unseen = estimate_unseen(
            self.entities,
            occasions=self._live_occasions(),
            withheld_planes=self._withheld,
        )
        unseen_delta = 0.0
        if self._prev_unseen_lower is not None:
            unseen_delta = unseen.lower - self._prev_unseen_lower
        health_delta: tuple[str, str] | None = None
        if (
            self._prev_health is not None
            and self._prev_health != unseen.coverage_health
        ):
            health_delta = (self._prev_health, unseen.coverage_health)

        self._prev_unseen_lower = unseen.lower
        self._prev_health = unseen.coverage_health
        self._seen_this_window.clear()

        return StreamDelta(
            confirmed_disappeared=presence_delta.confirmed_disappeared,
            unseen_fraction_delta=unseen_delta,
            coverage_health_delta=health_delta,
            occasions=self._live_occasions(),
        )

    # ------------------------------------------------------------------ internals

    def _live_occasions(self) -> tuple[PlaneId, ...]:
        """The capture occasions actually present in the live estate.

        Unions the configured occasion order with whatever planes the live
        entities were genuinely captured on, so the estimator counts only real
        vantages (ARCHITECTURE.md §6) while preserving the configured order.
        """
        live: set[PlaneId] = set()
        for t in self._tracked.values():
            live |= t.entity.planes_seen
        ordered = [p for p in self._occasions if p in live]
        extra = [p for p in sorted(live, key=str) if p not in self._occasions]
        return tuple(ordered + extra) or self._occasions

    def _register_incidence(self, inc: Incidence) -> None:
        self._inc_by_id[inc.incidence_id] = inc
        for kname, kval in inc.footprint.keys:
            self._block_index[(kname, kval)].add(inc.incidence_id)

    def _retire(self, key: str) -> None:
        """Remove a touched component's entity; its member incidences are kept.

        The incidences themselves stay in ``_inc_by_id`` / the block index (they
        are real observations) and are re-attached to the re-resolved entity; we
        only drop the stale entity projection and its key mapping.
        """
        tracked = self._tracked.pop(key, None)
        if tracked is None:
            return
        for mid in tracked.entity.incidences:
            self._key_of_inc.pop(mid, None)

    @staticmethod
    def _tokens_of(entity: SieveEntity) -> frozenset[str]:
        graph = entity.capability_graph
        if graph is None:
            return frozenset(entity.capability)
        return frozenset(e.capability for e in graph.edges)

    def _empty_delta(self) -> StreamDelta:
        return StreamDelta(occasions=self._live_occasions())


__all__ = [
    "StreamingResolver",
    "StreamDelta",
    "INSTANT_PLANES",
]
