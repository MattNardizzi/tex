"""Independent SIEVE speed benchmark harness (fixed seed).

Measures:
  1. TIME-TO-FIRST-DETECTION: first instant-plane Incidence -> provisional entity.
  2. TIME-TO-FULL-ESTATE @ 20 (real tex-enterprise fleet) and @ ~1000 synthetic.
  3. INCREMENTAL-UPDATE LATENCY p95 (feed->delta) + scale-invariance check.
"""

from __future__ import annotations

import random
import statistics
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

from tex.discovery.engine.models import (
    Admissibility,
    FootprintVector,
    Incidence,
    PlaneId,
)
from tex.discovery.engine.pipeline import run_slice
from tex.discovery.engine.stream import INSTANT_PLANES, StreamingResolver
from tex.stores.agent_registry import InMemoryAgentRegistry
from tex.stores.discovery_ledger import InMemoryDiscoveryLedger

SEED = 1729
random.seed(SEED)
_BASE = datetime(2026, 6, 23, 12, 0, 0, tzinfo=UTC)

FLEET = Path("/Users/matthewnardizzi/dev/tex-enterprise")


def _inc(plane, keys, *, attrs=None, ref="ref", at=None):
    return Incidence(
        plane_id=plane,
        footprint=FootprintVector.of(plane, keys, attrs or {}),
        catchability=1.0,
        admissibility=Admissibility.OBSERVED,
        raw_evidence_ref=ref,
        observed_at=at or _BASE,
    )


def _agent_inc(name, plane, *, ref, at=None):
    return _inc(
        plane,
        {"agent_external_id": name, "workspace_path": f"work/{name}.jsonl"},
        attrs={"action_type": "write"},
        ref=ref,
        at=at,
    )


def now():
    return time.perf_counter()


# ---------------------------------------------------------------------------
# 1. TIME-TO-FIRST-DETECTION
# ---------------------------------------------------------------------------
def bench_first_detection(trials=200):
    """Wall time from constructing/feeding the FIRST instant-plane incidence to
    a provisional entity present in new_entities. Median + p95 over warm trials."""
    # confirm ACTIONS_TRAIL/FS_WRITE are instant planes
    assert PlaneId.ACTIONS_TRAIL in INSTANT_PLANES
    assert PlaneId.FS_WRITE in INSTANT_PLANES

    times = []
    for i in range(trials):
        resolver = StreamingResolver(tenant_id=f"first-{i}")
        inc = _agent_inc(f"Agent{i}", PlaneId.ACTIONS_TRAIL, ref=f"r{i}")
        t0 = now()
        delta = resolver.feed(inc)
        t1 = now()
        assert delta.new_entities, "no provisional entity emitted"
        times.append((t1 - t0) * 1000.0)
    return {
        "median_ms": statistics.median(times),
        "p95_ms": sorted(times)[int(0.95 * len(times)) - 1],
        "max_ms": max(times),
        "n": trials,
    }


# ---------------------------------------------------------------------------
# 2a. TIME-TO-FULL-ESTATE @ 20 — REAL tex-enterprise fleet via run_slice
# ---------------------------------------------------------------------------
def bench_full_estate_20():
    """Cold full-estate resolution of the real 20-agent fleet through run_slice
    (SENSE -> FUSE -> ESTIMATE -> adapter project). Includes unseen CI."""
    actions_dir = FLEET / "runtime" / "logs"
    workspace_dir = FLEET / "workspace"
    if not actions_dir.exists():
        return {"error": f"missing {actions_dir}"}

    registry = InMemoryAgentRegistry()
    ledger = InMemoryDiscoveryLedger()
    t0 = now()
    result = run_slice(actions_dir, workspace_dir, registry, ledger)
    t1 = now()
    unseen = result.unseen
    ci = None
    if unseen is not None:
        ci = (
            getattr(unseen, "ci_low", None),
            getattr(unseen, "lower", None),
            getattr(unseen, "ci_high", None),
        )
    return {
        "seconds": t1 - t0,
        "entities": len(result.entities),
        "projected": result.projected,
        "unseen_ci": ci,
        "log_files": len(list(actions_dir.glob("*.jsonl"))),
    }


# ---------------------------------------------------------------------------
# 2b. SCALE @ ~1000 synthetic agents via streaming feed_batch + window
# ---------------------------------------------------------------------------
def _synth_incidences(n_agents, seed=SEED):
    rng = random.Random(seed)
    incs = []
    for i in range(n_agents):
        name = f"synth-{i:05d}"
        # each agent seen on both real planes (2 capture occasions), like the fleet
        for plane in (PlaneId.ACTIONS_TRAIL, PlaneId.FS_WRITE):
            jitter = timedelta(seconds=rng.randint(0, 3600))
            incs.append(
                _inc(
                    plane,
                    {
                        "agent_external_id": name,
                        "workspace_path": f"work/{name}.jsonl",
                    },
                    attrs={"action_type": "write"},
                    ref=f"{name}:{plane}",
                    at=_BASE + jitter,
                )
            )
    rng.shuffle(incs)
    return incs


def bench_full_estate_n(n_agents):
    """Cold full-estate build of n synthetic agents through the streaming
    resolver (feed_batch in chunks, then window() to close + estimate unseen).
    This is the apples-to-apples 'resolve the whole estate from scratch' time."""
    incs = _synth_incidences(n_agents)
    resolver = StreamingResolver(tenant_id="scale")
    t0 = now()
    CHUNK = 256
    for j in range(0, len(incs), CHUNK):
        resolver.feed_batch(incs[j : j + CHUNK])
    # close the window -> drives presence + online unseen re-estimate (the CI)
    wdelta = resolver.window()
    t1 = now()
    lower = getattr(wdelta, "unseen_lower", None)
    return {
        "n_agents": n_agents,
        "incidences": len(incs),
        "seconds": t1 - t0,
        "estate_size": resolver.estate_size,
        "unseen_lower": lower,
    }


# ---------------------------------------------------------------------------
# 3. INCREMENTAL-UPDATE LATENCY p95 + scale invariance
# ---------------------------------------------------------------------------
def bench_incremental_latency(background_sizes=(0, 100, 1000), updates=200):
    """For each pre-loaded background estate size, measure feed->delta latency
    for `updates` brand-new single agents. Confirms p95 < 2s and that latency
    does NOT scale with estate size."""
    out = {}
    for bg in background_sizes:
        resolver = StreamingResolver(tenant_id=f"inc-{bg}")
        if bg:
            resolver.feed_batch(_synth_incidences(bg, seed=SEED + bg))
        lat = []
        rng = random.Random(SEED + 7 + bg)
        for k in range(updates):
            name = f"live-{bg}-{k}-{rng.randint(0, 10**9)}"
            inc = _inc(
                PlaneId.ACTIONS_TRAIL,
                {"agent_external_id": name, "workspace_path": f"work/{name}.jsonl"},
                attrs={"action_type": "write"},
                ref=name,
            )
            t0 = now()
            resolver.feed(inc)
            t1 = now()
            lat.append((t1 - t0) * 1000.0)
        out[bg] = {
            "median_ms": statistics.median(lat),
            "p95_ms": sorted(lat)[int(0.95 * len(lat)) - 1],
            "max_ms": max(lat),
            "final_estate": resolver.estate_size,
        }
    return out


if __name__ == "__main__":
    print("=== 1. TIME-TO-FIRST-DETECTION ===")
    f = bench_first_detection()
    print(f)

    print("\n=== 2a. FULL ESTATE @ 20 (real fleet) ===")
    e20 = bench_full_estate_20()
    print(e20)

    print("\n=== 2b. FULL ESTATE @ 1000 (synthetic) ===")
    e1000 = bench_full_estate_n(1000)
    print(e1000)

    print("\n=== 3. INCREMENTAL LATENCY (vs background size) ===")
    inc = bench_incremental_latency()
    for bg, v in inc.items():
        print(f"  bg={bg}: {v}")
