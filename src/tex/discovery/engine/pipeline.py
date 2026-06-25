"""
SIEVE pipeline — the thin-vertical-slice orchestrator (ARCHITECTURE.md §10).

Wires the four stages over two genuinely-independent capture occasions:

    SENSE  (ActionsTrailSensor + FsWriteScanSensor → Incidence stream)
      │
    FUSE   (resolve → one SieveEntity per agent; cross-plane edge; stable id)
      │
    ESTIMATE (estimate_unseen → wide unseen-FRACTION + CI + named blind spots)
      │
    OUTPUT ADAPTER (project → registry.save + ledger.append → governable)

``run_slice`` is the single direct-test entrypoint. It is NOT wired into the
live ``_build_discovery_connectors`` (Phase 8) and only runs when a caller
invokes it — the master flag ``TEX_SIEVE_ENABLED`` gates the LIVE path, not the
direct tests. Inputs are configurable paths so a verifier can point the sensors
at its own planted shadow. Degrades to an empty result on missing inputs.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
import os
from typing import Mapping, Sequence

from tex.discovery.engine import adapter
from tex.discovery.engine.capability import map_capability
from tex.discovery.engine.disambiguate import (
    classify_agent_vs_human,
    resolve_shared_credential,
)
from tex.discovery.engine.estimate import estimate_unseen
from tex.discovery.engine.fuse import cohorts_by_credential, resolve
from tex.discovery.engine.models import (
    Incidence,
    PlaneId,
    SharedCredentialVerdict,
    SieveEntity,
    UnseenEstimate,
)
from tex.discovery.engine.sensors import (
    ActionsTrailSensor,
    FsWriteScanSensor,
    SenseContext,
    build_active_sensors,
)

#: The two real capture occasions the slice runs (ARCHITECTURE.md §10). Order
#: matters: occasion[0] = ACTIONS_TRAIL, occasion[1] = FS_WRITE feed the
#: two-occasion Lincoln-Petersen / Chao2 estimator as n1 / n2.
_SLICE_OCCASIONS: tuple[PlaneId, ...] = (PlaneId.ACTIONS_TRAIL, PlaneId.FS_WRITE)


@dataclass(frozen=True)
class SliceResult:
    """The headline object handle for one slice run (ARCHITECTURE.md §9).

    - ``entities``      — the resolved ``SieveEntity`` set (object handle, never
                          a forced agent table in the spoken surface).
    - ``unseen``        — the calibrated ``UnseenEstimate`` (lower + CI + named
                          blind spots) — the spoken honest-edge sentence.
    - ``projected``     — count of entities written through the governance
                          boundary (registry + ledger), so a test can assert the
                          adapter ran.
    - ``occasions`` / ``withheld_planes`` — the planes that captured vs were
                          deliberately withheld this run, for receipts.
    """

    entities: tuple[SieveEntity, ...] = ()
    unseen: UnseenEstimate | None = None
    projected: int = 0
    occasions: tuple[PlaneId, ...] = ()
    withheld_planes: tuple[PlaneId, ...] = field(default_factory=tuple)


def _empty_result(
    withheld_planes: tuple[PlaneId, ...],
) -> SliceResult:
    """A degenerate-but-honest result for missing/empty inputs.

    No entities were seen, so the estimator has no support; it returns a
    deliberately-wide ``degenerate`` estimate with a named blind spot per
    withheld plane. NEVER raises, NEVER fabricates an entity.
    """
    unseen = estimate_unseen(
        (),
        occasions=_SLICE_OCCASIONS,
        withheld_planes=withheld_planes,
    )
    return SliceResult(
        entities=(),
        unseen=unseen,
        projected=0,
        occasions=_SLICE_OCCASIONS,
        withheld_planes=withheld_planes,
    )


#: Footprint keys/attrs the agent-vs-human classifier reads, in the order the
#: ``disambiguate.classify_agent_vs_human`` ``signals`` mapping expects them. The
#: pipeline lifts these verbatim off an entity's member incidences so the
#: classifier sees whatever discriminating signal a sensor surfaced (canary
#: obedience, response latency, packetization, tool-grammar tightness, motor
#: noise). Absent everywhere ⇒ the classifier ABSTAINS — the honest default.
_AGENT_HUMAN_SIGNAL_KEYS: tuple[str, ...] = (
    "canary_obeyed",
    "response_ms",
    "packetization",
    "tool_grammar",
    "motor_noise",
)


def _agent_human_signals(
    entity: SieveEntity, by_id: dict,
) -> dict[str, str]:
    """Collect the agent-vs-human discriminating signals off an entity's members.

    Reads ``_AGENT_HUMAN_SIGNAL_KEYS`` from each member incidence's footprint
    (keys first, then attrs) and returns the first non-empty value seen per
    signal. Empty when no member carries any discriminating signal, in which case
    the classifier abstains rather than guessing (the honest default). Generic:
    any plane that surfaces one of these signals contributes without a code
    change.
    """
    signals: dict[str, str] = {}
    for mid in entity.incidences:
        inc = by_id.get(mid)
        if inc is None:
            continue
        for name in _AGENT_HUMAN_SIGNAL_KEYS:
            if name in signals:
                continue
            val = inc.footprint.key(name) or inc.footprint.attr(name)
            if val:
                signals[name] = val
    return signals


def resolve_full(
    incidences: Sequence[Incidence],
) -> tuple[SieveEntity, ...]:
    """Run the FULL FUSE + DISAMBIGUATE + CAPABILITY brain over an incidence set.

    This is the deepened resolution path the slice and the eval harness share. It
    is the single place the engine's four resolution collaborators are composed:

    1. FUSE — ``fuse.resolve`` resolves footprints into ``SieveEntity`` set
       (plane-typed correlation clustering: identity edges close transitively,
       bridging bridges across strong components emit the N1 split, contradicting
       strong planes set the N4 incoherence flags). The clusterer already attaches
       a structural ``SharedCredentialVerdict`` per credential.

    2. DISAMBIGUATE (shared-credential, N1) — ``disambiguate.resolve_shared_
       credential`` runs the richer BEHAVIORAL splitter (tool-grammar BIC +
       anytime-valid e-value + attestation clone-split) over every credential
       cohort. Its verdicts are MERGED onto the entities that carry the credential
       so each entity's ``shared_credential_verdicts`` reflects the behavioral k
       (the clusterer's structural verdict and the behavioral verdict agree on the
       benchmark planted cases; the behavioral one supersedes when present so the
       split count is the model-selected one).

    3. DISAMBIGUATE (agent-vs-human, §3B) — ``disambiguate.classify_agent_vs_
       human`` classifies each entity from whatever discriminating signals its
       member footprints carry; the calibrated verdict lands on
       ``entity.agent_human`` (ABSTAIN when no signal is present).

    4. CAPABILITY (§4) — ``capability.map_capability`` reconstructs each entity's
       graded blast-radius surface from its members' observed/proven/declared
       footprints; the graph lands on ``entity.capability_graph`` and the coarse
       exercised-token view is mirrored into ``entity.capability``.

    Returns the same entity objects ``fuse.resolve`` produced, now enriched in
    place. An empty input yields an empty tuple.
    """
    incs = list(incidences)
    if not incs:
        return ()

    by_id = {inc.incidence_id: inc for inc in incs}

    # 1. FUSE.
    entities = list(resolve(incs))

    # 2. DISAMBIGUATE — shared-credential behavioral split (N1).
    cohorts = cohorts_by_credential(incs)
    behavioral_verdicts = resolve_shared_credential(cohorts)
    _merge_credential_verdicts(entities, by_id, behavioral_verdicts)

    # 3. DISAMBIGUATE — agent-vs-human classification (§3B).
    for entity in entities:
        signals = _agent_human_signals(entity, by_id)
        entity.agent_human = classify_agent_vs_human(entity, signals)

    # 4. CAPABILITY — graded blast-radius surface (§4).
    for entity in entities:
        graph = map_capability(entity, incs)
        entity.capability_graph = graph
        # Mirror the coarse exercised-token list so existing readers keep working.
        entity.capability = tuple(
            sorted(
                e.capability for e in graph.edges if e.exercised
            )
        )

    return tuple(entities)


def _credential_of_entity(
    entity: SieveEntity, by_id: dict
) -> set[str]:
    """The set of bridging credential ids an entity's members were collapsed under.

    Mirrors ``fuse.cohorts_by_credential``'s id form (``"<key>=<value>"``) so the
    behavioral verdict and the entity can be matched on the SAME credential id.
    """
    creds: set[str] = set()
    for mid in entity.incidences:
        inc = by_id.get(mid)
        if inc is None:
            continue
        for name in ("agent_external_id", "service_credential", "egress_ip"):
            val = inc.footprint.key(name)
            if val is not None:
                creds.add(f"{name}={val}")
                break
    return creds


def _merge_credential_verdicts(
    entities: Sequence[SieveEntity],
    by_id: dict,
    behavioral_verdicts: Sequence[SharedCredentialVerdict],
) -> None:
    """Attach the behavioral shared-credential verdicts onto the matching entities.

    Each behavioral verdict names a ``credential_id``; it is attached to every
    entity whose members carry that credential. The structural verdict
    ``fuse.resolve`` already attached is KEPT (it names the same credential with
    the same k on the benchmark planted cases); the behavioral verdict is appended
    so a downstream reader can see the model-selected (BIC + e-value) split count
    and its calibrated confidence alongside the structural transitivity verdict.
    Idempotent on credential id — a behavioral verdict is not appended twice.
    """
    by_cred: dict[str, SharedCredentialVerdict] = {
        v.credential_id: v for v in behavioral_verdicts
    }
    for entity in entities:
        existing_ids = {
            v.credential_id
            for v in entity.shared_credential_verdicts
            if v.method
            in ("evalue_sequential_bic", "single_process", "attestation_clone_split")
            or "attestation" in v.method
        }
        for cred_id in _credential_of_entity(entity, by_id):
            verdict = by_cred.get(cred_id)
            if verdict is None or cred_id in existing_ids:
                continue
            entity.shared_credential_verdicts = (
                entity.shared_credential_verdicts + (verdict,)
            )


def run_slice(
    actions_dir: Path,
    workspace_dir: Path,
    registry,  # noqa: ANN001 - InMemoryAgentRegistry
    ledger,  # noqa: ANN001 - InMemoryDiscoveryLedger
    index=None,  # noqa: ANN001 - ReconciliationIndex (optional; built if None)
    withheld_planes: Sequence[PlaneId] = (PlaneId.WITHHELD_THIRD,),
) -> SliceResult:
    """Run the full thin slice end-to-end and return a ``SliceResult``.

    Stages:

    1. SENSE — build a ``SenseContext`` from the two configurable dirs; run
       ``ActionsTrailSensor`` (Occasion A) and ``FsWriteScanSensor`` (Occasion
       B, given the actions_dir so it can compute the claimed-vs-actual diff);
       collect every ``Incidence``. Missing dirs → empty (the sensors degrade).
    2. FUSE — ``resolve(incidences)`` → entities. A trail row and the file it
       wrote fuse on ``workspace_path`` into one entity; a gate-bypassing file
       with no trail row resolves to its OWN entity from FS_WRITE alone.
    3. ESTIMATE — ``estimate_unseen(entities, occasions=[ACTIONS_TRAIL,
       FS_WRITE], withheld_planes=...)`` → a deliberately-wide ``UnseenEstimate``
       with a named blind spot per withheld plane.
    4. OUTPUT ADAPTER — for each entity call ``adapter.project`` (registry.save
       then ledger.append); count the projections.

    Returns a ``SliceResult`` carrying entities, the estimate, the projected
    count, and the occasion/withheld plane sets. NEVER raises on missing inputs
    — it degrades to an empty ``SliceResult`` with a degenerate estimate.

    ``index`` defaults to a fresh ``ReconciliationIndex`` bootstrapped from the
    registry so a re-run re-links the same entities instead of churning them.
    """
    withheld = tuple(dict.fromkeys(withheld_planes))  # de-dup, preserve order

    if index is None:
        # Local import: the index lives in the service module and we only need
        # it lazily, keeping the engine import graph free of the service.
        from tex.discovery.service import ReconciliationIndex

        index = ReconciliationIndex(registry=registry)

    # ------------------------------------------------------------------
    # 1. SENSE — two genuinely-independent occasions. Sensors degrade to empty.
    # ------------------------------------------------------------------
    context = SenseContext(
        actions_dir=_as_path(actions_dir),
        workspace_dir=_as_path(workspace_dir),
    )

    incidences: list[Incidence] = []
    incidences.extend(ActionsTrailSensor().sense(context))
    incidences.extend(FsWriteScanSensor().sense(context))

    if not incidences:
        return _empty_result(withheld)

    # ------------------------------------------------------------------
    # 2. FUSE + DISAMBIGUATE + CAPABILITY — the full deepened brain.
    #    resolve_full applies the shared-credential behavioral split (N1), the
    #    agent-vs-human classification (§3B), and the graded capability surface
    #    (§4) on top of the plane-typed correlation clustering.
    # ------------------------------------------------------------------
    entities = resolve_full(incidences)

    # ------------------------------------------------------------------
    # 3. ESTIMATE — two-occasion capture-recapture; widen for each withheld.
    # ------------------------------------------------------------------
    unseen = estimate_unseen(
        entities,
        occasions=_SLICE_OCCASIONS,
        withheld_planes=withheld,
    )

    # ------------------------------------------------------------------
    # 4. OUTPUT ADAPTER — land each entity through the governance boundary.
    # ------------------------------------------------------------------
    projected = 0
    for entity in entities:
        adapter.project(entity, registry, ledger, index)
        projected += 1

    return SliceResult(
        entities=entities,
        unseen=unseen,
        projected=projected,
        occasions=_SLICE_OCCASIONS,
        withheld_planes=withheld,
    )


@dataclass(frozen=True)
class PlanesResult:
    """The headline object handle for one multi-plane registry-driven run.

    Mirrors ``SliceResult`` but reports the planes the FLAG-ENABLED roster
    actually captured on (not the fixed two slice occasions). The estimator's
    capture occasions are the union of planes that emitted at least one
    incidence, so the unseen-fraction is computed over the genuinely-independent
    vantages that were live this window (ARCHITECTURE.md §6, §8, §11).

    - ``entities``       — the resolved ``SieveEntity`` set across all live planes.
    - ``unseen``         — the calibrated ``UnseenEstimate`` over the live planes.
    - ``projected``      — count of entities written through the governance
                           boundary (registry + ledger).
    - ``occasions``      — the planes that genuinely captured this window (each
                           emitted >=1 incidence), the estimator's occasion set.
    - ``active_planes``  — every plane whose flag was enabled (built a sensor),
                           whether or not it captured — for receipts/coverage.
    - ``withheld_planes``— planes deliberately named as blind spots this run.
    """

    entities: tuple[SieveEntity, ...] = ()
    unseen: UnseenEstimate | None = None
    projected: int = 0
    occasions: tuple[PlaneId, ...] = ()
    active_planes: tuple[PlaneId, ...] = ()
    withheld_planes: tuple[PlaneId, ...] = field(default_factory=tuple)


def run_planes(
    env: Mapping[str, str] | None = None,
    *,
    context: SenseContext | None = None,
    registry=None,  # noqa: ANN001 - InMemoryAgentRegistry (optional)
    ledger=None,  # noqa: ANN001 - InMemoryDiscoveryLedger (optional)
    index=None,  # noqa: ANN001 - ReconciliationIndex (optional)
    withheld_planes: Sequence[PlaneId] = (PlaneId.WITHHELD_THIRD,),
    tenant_id: str = "default",
) -> PlanesResult:
    """SENSE across ALL flag-enabled planes → FUSE → ESTIMATE → ADAPT.

    The full-roster sibling of ``run_slice``. Instead of the two fixed slice
    sensors, it builds the active sensor set from the registry
    (``build_active_sensors(env)``) so the plane set is CONFIGURABLE and every
    plane is FLAG-GATED OFF by default (ARCHITECTURE.md §8). With no
    ``TEX_SIEVE_P*`` flags set, ``build_active_sensors`` returns ``[]`` and this
    function returns an empty, honest ``PlanesResult`` — the default-safe posture
    a merge-to-main / prod deploy must keep.

    Stages:

    1. SENSE — read ``env`` (defaults to ``os.environ``), build the flag-enabled
       sensor set, and ``sense`` each over ``context`` (the configurable input
       roots so a verifier can point the planes at its own planted estate). Each
       sensor degrades to empty on missing creds/sources and NEVER raises, so a
       partially-credentialed env yields fewer planes, never a crash. The set of
       planes that emitted >=1 incidence is the genuine capture-occasion set.

    2. FUSE — ``resolve_full`` runs the cross-plane plane-typed correlation
       clustering + N1 shared-credential split + agent-vs-human + capability over
       the WHOLE incidence stream, so the same agent seen on N planes fuses to one
       entity (cross-plane fusion is exactly what the multi-plane path unlocks).

    3. ESTIMATE — ``estimate_unseen`` treats the live planes as capture occasions
       and widens the band for each withheld plane (and for too-few occasions),
       emitting a named blind spot per withheld plane.

    4. ADAPT — when a ``registry``/``ledger`` boundary is supplied, project every
       entity through it (registry.save → ledger.append). When omitted, the run
       is a pure SENSE→FUSE→ESTIMATE pass (``projected == 0``) — useful for a
       coverage probe that must not mutate the registry.

    NEVER raises on missing inputs: an empty roster, an empty context, or an
    absent boundary all degrade to an honest result.
    """
    env = dict(env) if env is not None else dict(os.environ)
    context = context or SenseContext()
    withheld = tuple(dict.fromkeys(withheld_planes))  # de-dup, preserve order

    # ------------------------------------------------------------------
    # 1. SENSE — every flag-enabled plane; each degrades to empty, never raises.
    # ------------------------------------------------------------------
    sensors = build_active_sensors(env)
    active_planes = tuple(dict.fromkeys(s.plane_id for s in sensors))

    incidences: list[Incidence] = []
    captured: dict[PlaneId, None] = {}
    for sensor in sensors:
        for inc in sensor.sense(context):
            incidences.append(inc)
            captured.setdefault(inc.plane_id, None)
    occasions = tuple(captured.keys())

    if not incidences:
        # No live plane captured anything (no flags, or all planes degraded to
        # empty). Honest empty result: estimate over zero occasions is the wide
        # degenerate band with a named blind spot per withheld plane.
        unseen = estimate_unseen((), occasions=occasions, withheld_planes=withheld)
        return PlanesResult(
            entities=(),
            unseen=unseen,
            projected=0,
            occasions=occasions,
            active_planes=active_planes,
            withheld_planes=withheld,
        )

    # ------------------------------------------------------------------
    # 2. FUSE + DISAMBIGUATE + CAPABILITY — cross-plane over the whole stream.
    # ------------------------------------------------------------------
    entities = resolve_full(incidences)

    # ------------------------------------------------------------------
    # 3. ESTIMATE — live planes are the capture occasions; widen per withheld.
    # ------------------------------------------------------------------
    unseen = estimate_unseen(
        entities,
        occasions=occasions,
        withheld_planes=withheld,
    )

    # ------------------------------------------------------------------
    # 4. ADAPT — project through the governance boundary when one is supplied.
    # ------------------------------------------------------------------
    projected = 0
    if registry is not None and ledger is not None:
        if index is None:
            from tex.discovery.service import ReconciliationIndex

            index = ReconciliationIndex(registry=registry)
        for entity in entities:
            adapter.project(entity, registry, ledger, index, tenant=tenant_id)
            projected += 1

    return PlanesResult(
        entities=entities,
        unseen=unseen,
        projected=projected,
        occasions=occasions,
        active_planes=active_planes,
        withheld_planes=withheld,
    )


def run_stream(
    event_source,  # noqa: ANN001 - Iterable[Incidence | Sequence[Incidence]]
    registry=None,  # noqa: ANN001 - InMemoryAgentRegistry (optional sink)
    ledger=None,  # noqa: ANN001 - InMemoryDiscoveryLedger (optional sink)
    *,
    tenant_id: str = "default",
    index=None,  # noqa: ANN001 - ReconciliationIndex (optional)
    occasions: Sequence[PlaneId] = _SLICE_OCCASIONS,
    withheld_planes: Sequence[PlaneId] = (PlaneId.WITHHELD_THIRD,),
    missing_threshold: int = 3,
    resolver=None,  # noqa: ANN001 - StreamingResolver (optional; built if None)
    window_every: int | None = None,
    close_window: bool = True,
):
    """Drive the CONTINUOUS path: an event source → live deltas → adapter writes.

    The streaming sibling of ``run_slice``. Where ``run_slice`` accumulates a
    whole window then summarizes once (BATCH), ``run_stream`` consumes the sensor
    planes as an EVENT SOURCE and emits one ``StreamDelta`` per event/batch,
    re-resolving only the touched graph components and (when a registry+ledger
    sink is supplied) projecting each new/tightened entity through
    ``adapter.project`` (registry.save → ledger.append) per delta — registry-first
    / ledger-last, exactly like the batch boundary (ARCHITECTURE.md §5, §7).

    ``run_slice`` is untouched and keeps working unchanged; this is an additive
    second entrypoint.

    Args:
        event_source: an iterable of streaming events. Each event is either ONE
            ``Incidence`` (one-by-one ingest) or a ``Sequence[Incidence]`` (a
            small co-arriving batch sharing one bounded re-resolution pass). A
            connector's per-candidate iterator (service.py L358) becomes exactly
            this: each connector is an event source feeding ``Incidence`` records.
        registry / ledger: the optional output-adapter sink. When BOTH are given,
            every delta's new/tightened entities land through the governance
            boundary so ``StandingGovernance.decide`` can govern them. When
            omitted, ``run_stream`` is a pure SENSE→FUSE delta pass (no writes).
        tenant_id: the tenant the presence machine + adapter key on.
        index: optional ``ReconciliationIndex`` (built from the registry if None).
        occasions / withheld_planes: the estimator's capture-occasion order and
            the deliberately-withheld blind-spot planes (online unseen estimate).
        missing_threshold: N-consecutive-miss threshold for confirmed
            disappearance (false-positive suppression).
        resolver: an existing ``StreamingResolver`` to drive (advanced callers
            that share one resolver across sources); built fresh if None.
        window_every: if set, close a presence/unseen WINDOW after every this-many
            events (so disappearance + online completeness deltas surface mid-
            stream). If None, windows are only closed at the end (when
            ``close_window`` is True).
        close_window: when True (default), a final ``window()`` is closed after
            the source is exhausted so the last window's disappearance + unseen
            deltas are emitted.

    Yields:
        ``StreamDelta`` objects: one per event/batch (the ingest delta), plus one
        per window close (the presence + online-completeness delta). A caller that
        only wants the final state can drain the generator and read the resolver.

    NEVER raises on an empty/None source — it simply yields nothing (or only the
    final window delta when ``close_window`` is True).
    """
    from tex.discovery.engine.stream import StreamingResolver

    if resolver is None:
        resolver = StreamingResolver(
            tenant_id=tenant_id,
            occasions=tuple(occasions),
            withheld_planes=tuple(withheld_planes),
            missing_threshold=missing_threshold,
            registry=registry,
            ledger=ledger,
            index=index,
        )

    if event_source is None:
        if close_window:
            yield resolver.window()
        return

    seen = 0
    for event in event_source:
        if event is None:
            continue
        # One Incidence → feed; a sequence of Incidence → feed_batch.
        if isinstance(event, Incidence):
            yield resolver.feed(event)
        else:
            yield resolver.feed_batch(event)
        seen += 1
        if window_every is not None and seen % window_every == 0:
            yield resolver.window()

    if close_window:
        yield resolver.window()


def _as_path(value: Path | str | None) -> Path | None:
    """Coerce a path-or-string-or-None to a ``Path`` without raising.

    The sensors already guard ``None`` / missing dirs, so this only normalizes
    the type; an odd value degrades to ``None`` rather than raising.
    """
    if value is None:
        return None
    try:
        return Path(value)
    except TypeError:
        return None


__all__ = [
    "SliceResult",
    "run_slice",
    "resolve_full",
    "PlanesResult",
    "run_planes",
    "run_stream",
]
