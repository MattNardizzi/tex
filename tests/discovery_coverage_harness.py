"""
SIEVE Layer-A COVERAGE HARNESS — the verifier's tooling (NOT the product path).

This module plants, NON-COOPERATIVELY, at least one instance of EVERY discovery
archetype the brief enumerates (a)..(k), runs the FULL SIEVE engine over the
plants (``resolve_full`` + ``estimate_unseen`` for the in-memory archetypes;
``pipeline.run_planes`` over temp fixture dirs for the file-sensor archetypes),
and exposes the three helpers an independent verifier calls:

    plant_all()                       -> PlantedEstate
    run_full_engine(planted)          -> EngineResult (entities + unseen estimate)
    mutate(plant)                     -> a mutated copy of one plant

The HONESTY GATE (non-negotiable, ARCHITECTURE.md §6/§12, BLIND_SPOT_REGISTER):

* Every CATCHABLE archetype maps to a REAL planted agent the engine actually
  surfaced — no archetype is "claimed found" without a resolved entity carrying
  its planted ground-truth label.
* The DECOYS (i) must NOT inflate the agent count (a human-using-an-LLM, a
  dormant identity, and a duplicate signal of one agent).
* The SHARED-CREDENTIAL pair (h) must resolve to TWO entities, never one.
* The PHYSICALLY-IRREDUCIBLE agent (k) is NEVER planted as an observable
  incidence. It is declared as an EXPECTATION that the engine must NOT find it
  and must NAME its missing vantage in the blind-spot ledger. It is the only
  archetype with no resolved entity — by design.

GROUND TRUTH is carried in ``Incidence.raw_evidence_ref`` as ``truth=<label>``
(the eval-harness convention) so it NEVER leaks into a matchable footprint key.

The harness NEVER mutates the real tex-enterprise fleet. It plants into temp
fixture dirs it owns. It ALSO offers ``real_fleet_context()`` to run the engine
read-only over the REAL fleet logs+workspace to demonstrate the hard case on real
data (the gate-bypass shadow surfaced from the filesystem alone).
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Iterable
from uuid import UUID

from tex.discovery.engine.estimate import estimate_unseen
from tex.discovery.engine.models import (
    Admissibility,
    FootprintVector,
    Incidence,
    PlaneId,
    SieveEntity,
    UnseenEstimate,
)
from tex.discovery.engine.pipeline import PlanesResult, resolve_full, run_planes
from tex.discovery.engine.sensors.base import SenseContext

# The real fleet (read-only). Used ONLY by ``real_fleet_context`` — never written.
REAL_FLEET_ROOT = Path("/Users/matthewnardizzi/dev/tex-enterprise")
REAL_FLEET_LOGS = REAL_FLEET_ROOT / "runtime" / "logs"
REAL_FLEET_WORKSPACE = REAL_FLEET_ROOT / "workspace"

#: The two slice occasions plus the breadth planes the planted estate spans. The
#: estimator counts the planes that genuinely captured >=1 entity as occasions.
_BASE_OCCASIONS: tuple[PlaneId, ...] = (
    PlaneId.ACTIONS_TRAIL,
    PlaneId.FS_WRITE,
    PlaneId.KERNEL_EBPF,
    PlaneId.GOVERNANCE_STREAM,
    PlaneId.NETWORK_EGRESS,
    PlaneId.SIGNED_ID,
    PlaneId.STATIC_SUPPLYCHAIN,
    PlaneId.MCP_TOOLGRAPH,
)

#: A monotone clock so every planted incidence is tz-aware and ordered.
_T0 = datetime(2026, 5, 1, 12, 0, 0, tzinfo=UTC)


def _at(seconds: int) -> datetime:
    return _T0 + timedelta(seconds=seconds)


# ---------------------------------------------------------------------------
# Archetype registry — the named catalogue the verifier asserts against.
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Archetype:
    """One planted discovery archetype.

    - ``key``         — the brief's letter, "a".."k".
    - ``label``       — the planted ground-truth agent label (``truth=<label>``).
    - ``description`` — what the archetype IS and which vantage should catch it.
    - ``cooperative`` — ALWAYS False for the agents (planted non-cooperatively).
                        The credentialed cloud identity (e) and the static (g)
                        carry a real platform identity but DO NOT self-register
                        with Tex — they are discovered, not onboarded.
    - ``catchable``   — True for every archetype the engine MUST surface; False
                        ONLY for (k) the physically-irreducible agent, which the
                        engine must NAME as a blind spot, never find.
    - ``expected_entities`` — how many distinct entities this archetype's
                        footprints must resolve to (2 for the shared-cred pair,
                        0 for the decoys-that-are-not-new-agents and for (k)).
    """

    key: str
    label: str
    description: str
    cooperative: bool
    catchable: bool
    expected_entities: int


_ARCHETYPES: tuple[Archetype, ...] = (
    Archetype(
        "a",
        "laptop-local-noidp",
        "laptop-local process, no IdP identity — caught via kernel/eBPF "
        "(exec+syscall-graph) and the fs/actions behavioral plane.",
        cooperative=False,
        catchable=True,
        expected_entities=1,
    ),
    Archetype(
        "b",
        "inproc-embedded-thread",
        "in-process embedded thread agent (no own PID-as-agent) — caught via "
        "the governance-stream PDP plane + network behavioral + tool-grammar.",
        cooperative=False,
        catchable=True,
        expected_entities=1,
    ),
    Archetype(
        "c",
        "stdio-mcp-server",
        "stdio-only MCP server (no network listener) — caught via kernel/eBPF "
        "stdio + static manifest + the MCP tool-graph.",
        cooperative=False,
        catchable=True,
        expected_entities=1,
    ),
    Archetype(
        "d",
        "egress-only-noidp",
        "egress-only agent (no identity) — caught ONLY by outbound LLM/API "
        "calls on the network plane.",
        cooperative=False,
        catchable=True,
        expected_entities=1,
    ),
    Archetype(
        "e",
        "credentialed-cloud",
        "credentialed cloud identity (the EASY case) — must resolve and must "
        "NOT double-count across its signed-id + control-plane sightings.",
        cooperative=False,  # has a real SP identity but does NOT onboard with Tex
        catchable=True,
        expected_entities=1,
    ),
    Archetype(
        "f",
        "pdp-only-agent",
        "PDP-only agent (does nothing observable except call Tex's PDP) — "
        "self-discovered by the governance-stream plane.",
        cooperative=False,
        catchable=True,
        expected_entities=1,
    ),
    Archetype(
        "g",
        "static-prerun-agent",
        "static / pre-runtime agent (defined in a repo/manifest but NOT yet "
        "running) — caught by the static/supply-chain plane.",
        cooperative=False,
        catchable=True,
        expected_entities=1,
    ),
    Archetype(
        "h",
        "shared-cred-pair",
        "SHARED-CREDENTIAL pair: two distinct agents behind one service "
        "principal — must resolve to TWO entities, not one (N1 split).",
        cooperative=False,
        catchable=True,
        expected_entities=2,
    ),
    Archetype(
        "i",
        "decoys",
        "DECOYS / false-positive bait: a human-using-an-LLM, a dormant "
        "identity, and a duplicate signal of one agent — must NOT be reported "
        "as new agents.",
        cooperative=False,
        catchable=True,  # the duplicate's ONE real agent is found; the bait is not
        expected_entities=1,  # exactly ONE real agent behind the duplicate signal
    ),
    Archetype(
        "j",
        "evasive-catchable",
        "EVASIVE agents (catchable variants): domain-fronting/CDN-masked SNI, "
        "randomized JA3, session-piggybacking, in-allowed-process, batching — "
        "caught via multi-plane corroboration / N4 incoherence / behavioral.",
        cooperative=False,
        catchable=True,
        expected_entities=1,
    ),
    Archetype(
        "k",
        "irreducible-airgapped",
        "PHYSICALLY IRREDUCIBLE agent (self-hosted/air-gapped model, no egress, "
        "no IdP, no PDP call) — engine MUST name it a blind spot, NOT find it.",
        cooperative=False,
        catchable=False,
        expected_entities=0,
    ),
    Archetype(
        "m",
        "hostile-shared-ja4",
        "HOSTILE over-merge trap: two DISTINCT agents sharing one POPULAR JA4 "
        "(a low-entropy network bridge shared by many footprints) — the N5 "
        "anonymity-set / over-merge bar must hold and resolve them to TWO "
        "distinct entities, never collapse the popular bridge into one.",
        cooperative=False,
        catchable=True,
        expected_entities=2,
    ),
)


def archetypes() -> tuple[Archetype, ...]:
    """The full archetype catalogue (a)..(k)."""
    return _ARCHETYPES


def archetype(key: str) -> Archetype:
    for a in _ARCHETYPES:
        if a.key == key:
            return a
    raise KeyError(key)


# ---------------------------------------------------------------------------
# Incidence builder — ground truth in the evidence ref, never a matchable key.
# ---------------------------------------------------------------------------


def _inc(
    plane: PlaneId,
    *,
    keys: dict[str, str],
    truth: str,
    attrs: dict[str, str] | None = None,
    admissibility: Admissibility = Admissibility.OBSERVED,
    catchability: float = 1.0,
    at_s: int = 0,
) -> Incidence:
    """One planted footprint. ``truth`` lands in ``raw_evidence_ref`` ONLY."""
    return Incidence(
        plane_id=plane,
        footprint=FootprintVector.of(plane, keys=keys, attrs=attrs or {}),
        catchability=catchability,
        admissibility=admissibility,
        raw_evidence_ref=f"plant://{truth}",
        observed_at=_at(at_s),
    )


def truth_of(inc: Incidence) -> str:
    """The planted ground-truth label of an incidence (or '' if unplanted)."""
    ref = inc.raw_evidence_ref or ""
    if ref.startswith("plant://"):
        return ref[len("plant://") :]
    return ""


# ---------------------------------------------------------------------------
# The planted estate.
# ---------------------------------------------------------------------------


@dataclass
class PlantedEstate:
    """Everything ``plant_all`` produced.

    - ``incidences``         — every in-memory footprint fed to ``resolve_full``.
    - ``by_archetype``       — archetype key -> the incidence ids it planted.
    - ``fixture_root``       — temp dir holding the FILE-SENSOR fixtures (eBPF /
                               EDR / network-flow / static-repo) and the planted
                               actions/workspace dirs, so ``run_planes`` can sense
                               them. ``None`` when the caller planted in-memory only.
    - ``plane_env``          — the ``TEX_SIEVE_*`` flag+source env that activates
                               the file-sensor planes over ``fixture_root``.
    - ``occasions``          — the capture-occasion order for the estimator.
    - ``withheld_planes``    — deliberately-named blind-spot planes (always
                               includes the air-gapped (k) vantage).
    - ``irreducible_label``  — the (k) agent's label, asserted ABSENT from results.
    """

    incidences: list[Incidence] = field(default_factory=list)
    by_archetype: dict[str, list[UUID]] = field(default_factory=dict)
    fixture_root: Path | None = None
    plane_env: dict[str, str] = field(default_factory=dict)
    occasions: tuple[PlaneId, ...] = _BASE_OCCASIONS
    withheld_planes: tuple[PlaneId, ...] = (PlaneId.WITHHELD_THIRD, PlaneId.HONEYTOKEN)
    irreducible_label: str = "irreducible-airgapped"

    def ids_for(self, key: str) -> list[UUID]:
        return self.by_archetype.get(key, [])

    def incidences_for(self, key: str) -> list[Incidence]:
        ids = set(self.by_archetype.get(key, []))
        return [i for i in self.incidences if i.incidence_id in ids]


# ---------------------------------------------------------------------------
# plant_all — every archetype (a)..(k), planted non-cooperatively.
# ---------------------------------------------------------------------------


def plant_all(tmp_path: Path | None = None) -> PlantedEstate:
    """Plant at least one instance of EVERY archetype (a)..(k).

    Returns a ``PlantedEstate``. When ``tmp_path`` is given, the file-sensor
    archetypes (laptop-local eBPF, stdio-MCP manifest, egress-flow, static-repo)
    are ALSO written as real fixtures under ``tmp_path`` and ``plane_env`` is
    populated so ``run_planes`` can sense them through the REAL sensors. The
    in-memory ``incidences`` are the spine every archetype is represented on so
    the proof never depends on the optional file-sensor pass.
    """
    estate = PlantedEstate()
    add = _Adder(estate)

    _plant_laptop_local(add)        # (a)
    _plant_inproc_thread(add)       # (b)
    _plant_stdio_mcp(add)           # (c)
    _plant_egress_only(add)         # (d)
    _plant_credentialed_cloud(add)  # (e)
    _plant_pdp_only(add)            # (f)
    _plant_static_prerun(add)       # (g)
    _plant_shared_cred_pair(add)    # (h)
    _plant_decoys(add)              # (i)
    _plant_evasive(add)             # (j)
    # (k) the irreducible agent is DELIBERATELY NOT planted as any incidence.
    _plant_hostile(add)             # (m)

    if tmp_path is not None:
        estate.fixture_root = tmp_path
        estate.plane_env = _write_file_fixtures(tmp_path)

    return estate


class _Adder:
    """Tiny helper to append incidences and record their archetype provenance."""

    def __init__(self, estate: PlantedEstate) -> None:
        self.estate = estate

    def __call__(self, key: str, *incs: Incidence) -> None:
        self.estate.by_archetype.setdefault(key, [])
        for inc in incs:
            self.estate.incidences.append(inc)
            self.estate.by_archetype[key].append(inc.incidence_id)


# --- (a) laptop-local process, no IdP identity -----------------------------


def _plant_laptop_local(add: _Adder) -> None:
    """A python agent on a laptop with NO directory identity.

    Visible on the kernel/eBPF plane (exec + code_hash + syscall-graph split
    axis) and on the fs-write behavioral plane (a file it wrote). It NEVER
    appears on signed_id / managed_control — it has no cloud principal. The two
    sightings fuse on the IDENTITY-grade ``code_hash``.
    """
    code = "aa11" * 16  # 64 hex
    syscall = "scg-laptoplocal-01"
    add(
        "a",
        _inc(
            PlaneId.KERNEL_EBPF,
            keys={
                "code_hash": code,
                "syscall_graph_sig": syscall,
                "exec_id": "E:laptop:4471",
                "binary_path": "/usr/bin/python3.12",
            },
            attrs={"binary": "python3.12", "arguments": "-m localtool.main"},
            truth="laptop-local-noidp",
            admissibility=Admissibility.PROVEN,
            at_s=1,
        ),
        _inc(
            PlaneId.FS_WRITE,
            keys={"code_hash": code, "workspace_path": "local/scratch/out-9912.md"},
            attrs={"bytes": "318", "gate_bypass": "true", "behavior_sig": syscall},
            truth="laptop-local-noidp",
            admissibility=Admissibility.PROVEN,
            at_s=2,
        ),
    )


# --- (b) in-process / embedded thread agent --------------------------------


def _plant_inproc_thread(add: _Adder) -> None:
    """An embedded thread agent: no PID of its own (shares the host interpreter).

    It has no exec/code_hash leaf distinct from the host, so the kernel PID plane
    cannot individuate it (BS-11). It IS individuated by the governance-stream
    PDP plane (it makes its own PDP calls under its own logical agent id) joined
    to a network behavioral sighting via a shared injected behavioral signature.
    """
    behavior = "bsig-inproc-thread-7"
    add(
        "b",
        _inc(
            PlaneId.GOVERNANCE_STREAM,
            keys={"pdp_agent_id": "thread-agent://reconciler", "behavior_sig": behavior},
            attrs={"tool_name": "ledger.reconcile", "otel_trace_id": "tr-77a"},
            truth="inproc-embedded-thread",
            admissibility=Admissibility.OBSERVED,
            at_s=3,
        ),
        _inc(
            PlaneId.NETWORK_EGRESS,
            keys={
                "behavior_sig": behavior,
                "sni": "api.anthropic.com",
                "ja4": "t13d1516h2_8daaf6152771_b186095e22b6",
                "token_waveform_sig": "bundled:periodic",
            },
            attrs={"packetization_mode": "bundled", "tool_grammar": "tight"},
            truth="inproc-embedded-thread",
            admissibility=Admissibility.OBSERVED,
            at_s=4,
        ),
    )


# --- (c) stdio-only MCP server ---------------------------------------------


def _plant_stdio_mcp(add: _Adder) -> None:
    """A localhost MCP server spoken to over stdio — ZERO network signal.

    Invisible to every network tap (BS-02). Caught by the kernel/eBPF stdio
    vantage (an exec with stdio fds, no socket) joined to its static manifest and
    the MCP tool-graph via the IDENTITY-grade tool-set MinHash. The three
    sightings fuse on ``tool_set_minhash`` + ``code_hash``.
    """
    code = "bb22" * 16
    minhash = "minhash-stdio-mcp-files"
    add(
        "c",
        _inc(
            PlaneId.KERNEL_EBPF,
            keys={
                "code_hash": code,
                "syscall_graph_sig": "scg-stdio-mcp",
                "exec_id": "E:stdio:5120",
                "binary_path": "/opt/mcp/files-server",
            },
            attrs={"transport": "stdio", "has_socket": "false"},
            truth="stdio-mcp-server",
            admissibility=Admissibility.PROVEN,
            at_s=5,
        ),
        _inc(
            PlaneId.MCP_TOOLGRAPH,
            keys={"tool_set_minhash": minhash, "code_hash": code},
            attrs={"transport": "stdio", "tools": "read_file,write_file,list_dir"},
            truth="stdio-mcp-server",
            admissibility=Admissibility.OBSERVED,
            at_s=6,
        ),
        _inc(
            PlaneId.STATIC_SUPPLYCHAIN,
            keys={
                "tool_set_minhash": minhash,
                "manifest_path": "mcp-servers/files.json",
                "repo_path": "repo/mcp-files",
            },
            attrs={"framework": "mcp", "declared_tools": "read_file,write_file,list_dir"},
            truth="stdio-mcp-server",
            admissibility=Admissibility.CLAIMED,
            at_s=7,
        ),
    )


# --- (d) egress-only agent, no identity ------------------------------------


def _plant_egress_only(add: _Adder) -> None:
    """An agent whose ONLY footprint is an outbound LLM API call.

    No IdP, no PDP, no fs write, no exec on a host we instrument — the ONLY
    plane that can see it is the passive network-egress plane (bundled token
    waveform to an LLM provider). It resolves to its own entity from that single
    sighting (a singleton in the spectrum).
    """
    add(
        "d",
        _inc(
            PlaneId.NETWORK_EGRESS,
            keys={
                "ja4": "t13d1516h2_aaaaaa222222_cccccc333333",
                "sni": "api.openai.com",
                "asn": "AS13335",
                "egress_ip": "104.18.7.99",
                "token_waveform_sig": "bundled:periodic",
                "cadence_sig": "periodic-low-entropy",
            },
            attrs={
                "packetization_mode": "bundled",
                "model_provider": "openai",
                "metadata_only": "true",
            },
            truth="egress-only-noidp",
            admissibility=Admissibility.OBSERVED,
            at_s=8,
        ),
    )


# --- (e) credentialed cloud identity (the easy case) -----------------------


def _plant_credentialed_cloud(add: _Adder) -> None:
    """A managed cloud agent with a real signed directory identity.

    The EASY case: it carries a signed OIDC subject (identity-grade) AND a
    control-plane managed-agent-id. Its two sightings (signed_id + managed
    control) MUST fuse to ONE entity — it must NOT double-count. It does NOT
    self-register with Tex; it is discovered from the directory + control plane.
    """
    oidc = "oidc-sub://sp-billing-agent-42"
    managed = "managed-agent://bedrock/billing-agent-42"
    add(
        "e",
        _inc(
            PlaneId.SIGNED_ID,
            keys={"oidc_sub": oidc, "sp_object_id": "sp-42", "managed_agent_id": managed},
            attrs={"directory": "entra", "display_name": "billing-agent"},
            truth="credentialed-cloud",
            admissibility=Admissibility.PLATFORM_ATTESTED,
            at_s=9,
        ),
        _inc(
            PlaneId.MANAGED_CONTROL,
            keys={
                "managed_agent_id": managed,
                "oidc_sub": oidc,
                "control_plane": "bedrock",
                "model": "claude-3",
                "region": "us-east-1",
            },
            attrs={"role_arn": "arn:aws:iam::1:role/billing"},
            truth="credentialed-cloud",
            admissibility=Admissibility.PLATFORM_ATTESTED,
            at_s=10,
        ),
    )


# --- (f) PDP-only agent ----------------------------------------------------


def _plant_pdp_only(add: _Adder) -> None:
    """An agent that does NOTHING observable except call Tex's PDP.

    No fs write, no egress, no exec we see, no directory identity. The ONLY
    vantage that sees it is the governance-stream PDP plane (it asks the PDP for
    a decision). Self-discovered there as one entity from one sighting.
    """
    add(
        "f",
        _inc(
            PlaneId.GOVERNANCE_STREAM,
            keys={"pdp_agent_id": "pdp-only://quiet-advisor", "behavior_sig": "bsig-pdponly"},
            attrs={"tool_name": "policy.check", "otel_trace_id": "tr-pdp-only"},
            truth="pdp-only-agent",
            admissibility=Admissibility.OBSERVED,
            at_s=11,
        ),
    )


# --- (g) static / pre-runtime agent ----------------------------------------


def _plant_static_prerun(add: _Adder) -> None:
    """An agent DEFINED in a repo/manifest but NOT yet running.

    Zero runtime footprint (no exec, no egress, no PDP). Caught ONLY by the
    static / supply-chain plane parsing the repo agent definition. One CLAIMED
    sighting → one entity (pre-runtime; capability is declared-only).
    """
    add(
        "g",
        _inc(
            PlaneId.STATIC_SUPPLYCHAIN,
            keys={
                "agent_def_symbol": "nightly_reporter",
                "repo_path": "repo/agents/nightly_reporter.py",
                "manifest_path": "repo/agents/agent.toml",
            },
            attrs={
                "framework": "langgraph",
                "declared_tools": "fetch,summarize,email",
                "iam_role": "arn:aws:iam::1:role/reporter",
                "running": "false",
            },
            truth="static-prerun-agent",
            admissibility=Admissibility.CLAIMED,
            at_s=12,
        ),
    )


# --- (h) shared-credential pair (must split to TWO) ------------------------


def _plant_shared_cred_pair(add: _Adder) -> None:
    """TWO distinct agents behind ONE service principal.

    They share a BRIDGING-grade ``service_credential`` (the SP tex_gate trusts
    blindly) but carry DISTINCT identity-grade behavioral fingerprints. The
    strong-edge transitive-closure FAILURE across the credential bridge is the N1
    split → TWO entities, never one. Each agent has two footprints linked by its
    OWN ``behavior_sig``.
    """
    cred = "svc-shared-principal-h"
    for name, seq in (
        ("shared-cred-A", "query>summarize>write"),
        ("shared-cred-B", "deploy>rollback>deploy"),
    ):
        add(
            "h",
            _inc(
                PlaneId.GOVERNANCE_STREAM,
                keys={"service_credential": cred, "behavior_sig": f"bs-{name}"},
                attrs={"tool_name": "varies", "sequence": seq},
                truth=name,
                admissibility=Admissibility.OBSERVED,
                at_s=13,
            ),
            _inc(
                PlaneId.NETWORK_EGRESS,
                keys={"service_credential": cred, "behavior_sig": f"bs-{name}"},
                attrs={"sequence": seq, "packetization_mode": "bundled"},
                truth=name,
                admissibility=Admissibility.OBSERVED,
                at_s=14,
            ),
        )


# --- (i) decoys / false-positive bait --------------------------------------


def _plant_decoys(add: _Adder) -> None:
    """Three false-positive baits that must NOT inflate the agent count.

    1. HUMAN-using-an-LLM: a 1:1-packetized, high-entropy-cadence, no-canary
       network sighting. The agent-vs-human classifier must NOT label it AGENT;
       it is its own (human) entity but is NOT a discovered AGENT.
    2. DORMANT identity: a signed directory principal that emitted no runtime
       footprint. It is a CLAIMED identity with no exercised behavior.
    3. DUPLICATE signal of ONE real agent: the same agent seen twice on the same
       plane with the SAME identity key — must collapse to ONE entity, not two.

    Only the duplicate's underlying agent is a real discovered agent (ONE
    entity). The human and dormant baits must not be counted as new AGENTS.
    """
    # 1. human-using-an-LLM (its own entity, but classified HUMAN/ABSTAIN).
    add(
        "i",
        _inc(
            PlaneId.NETWORK_EGRESS,
            keys={
                "ja4": "t13d1516h2_humanbrowser_0001",
                "sni": "chat.openai.com",
                "egress_ip": "104.18.7.55",
            },
            attrs={
                "packetization_mode": "1:1",
                "cadence_sig": "bursty-high-entropy",
                "canary_obeyed": "false",
                "motor_noise": "present",
                "response_ms": "8200",
            },
            truth="decoy-human",
            admissibility=Admissibility.OBSERVED,
            at_s=15,
        ),
    )
    # 2. dormant directory identity (claimed, no behavior).
    add(
        "i",
        _inc(
            PlaneId.SIGNED_ID,
            keys={"oidc_sub": "oidc-sub://dormant-sp-99", "sp_object_id": "sp-99"},
            attrs={"directory": "entra", "enabled": "false", "last_sign_in": "never"},
            truth="decoy-dormant",
            admissibility=Admissibility.PLATFORM_ATTESTED,
            at_s=16,
        ),
    )
    # 3. duplicate signal of ONE real agent (same identity key twice → one entity).
    dup_code = "cc33" * 16
    add(
        "i",
        _inc(
            PlaneId.KERNEL_EBPF,
            keys={"code_hash": dup_code, "syscall_graph_sig": "scg-dup", "exec_id": "E:dup:1"},
            attrs={"note": "first sighting"},
            truth="decoy-duplicate",
            admissibility=Admissibility.PROVEN,
            at_s=17,
        ),
        _inc(
            PlaneId.KERNEL_EBPF,
            keys={"code_hash": dup_code, "syscall_graph_sig": "scg-dup", "exec_id": "E:dup:2"},
            attrs={"note": "duplicate sighting of the SAME agent"},
            truth="decoy-duplicate",
            admissibility=Admissibility.PROVEN,
            at_s=18,
        ),
    )


# --- (j) evasive agents (catchable variants) -------------------------------


def _plant_evasive(add: _Adder) -> None:
    """An evader caught by multi-plane corroboration + N4 incoherence.

    This agent domain-fronts (CDN-masked SNI), randomizes its JA3/JA4 per-flow
    (so no single network key recurs), session-piggybacks inside an allowed
    process, and batches to defeat cadence fingerprinting. EACH single-plane
    evasion succeeds — but the agent is caught because:

      * the eBPF host plane PROVES the exec + code_hash regardless of any network
        spoof (network evasion is irrelevant to the kernel vantage), and
      * its signed identity says "research-agent" while its tool-grammar /
        behavior says "deploy-agent" — a CONTRADICTING strong-edge plane-PAIR
        that the N4 incoherence detector raises as a positive find.

    The two sightings fuse on the IDENTITY-grade ``code_hash``; the SIGNED
    behavioral attribution (what the cert claims) CONTRADICTS the OBSERVED
    behavioral attribution (what it does), so two strong planes carry DIFFERENT
    identity-grade ``behavior_sig`` values for the one fused entity — the N4
    incoherence detector raises ``attribution_conflict`` and records the
    contradicting plane-PAIR. This is the compromised-but-still-signing case AIP
    cannot catch (ARCHITECTURE.md §2, N4).
    """
    code = "dd44" * 16
    add(
        "j",
        _inc(
            PlaneId.KERNEL_EBPF,
            keys={
                "code_hash": code,
                "syscall_graph_sig": "scg-evasive",
                "exec_id": "E:evasive:9001",
                "binary_path": "/usr/bin/python3.12",
                # What the SIGNED cert baked into the binary CLAIMS this agent is.
                "behavior_sig": "bs-evasive-research-SIGNED",
            },
            attrs={
                "binary": "python3.12",
                "signed_role": "research-agent",   # what it CLAIMS via its cert
                "network_evasion": "domain-fronting,ja3-rotation,batching",
            },
            truth="evasive-catchable",
            admissibility=Admissibility.PROVEN,
            at_s=19,
        ),
        _inc(
            PlaneId.GOVERNANCE_STREAM,
            keys={
                "code_hash": code,
                # What it ACTUALLY does — a DIFFERENT identity-grade behavior_sig
                # than the signed cert claims → the N4 contradiction across two
                # strong planes (KERNEL_EBPF vs GOVERNANCE_STREAM).
                "behavior_sig": "bs-evasive-deploy-OBSERVED",
            },
            attrs={
                "tool_name": "infra.deploy",
                "tool_grammar": "deploy>rollback>deploy",
                "behavior_role": "deploy-agent",   # what it DOES (tool-grammar)
            },
            truth="evasive-catchable",
            admissibility=Admissibility.OBSERVED,
            at_s=20,
        ),
    )


# --- (m) HOSTILE over-merge trap: two agents sharing one popular JA4 -------


#: A POPULAR JA4 — a low-entropy network fingerprint shared by many distinct
#: footprints (a stock Chrome/curl-impersonate hello). On its own it is a
#: BRIDGING-grade key whose anonymity set is large, so the N5
#: ``1/anonymity_set_size`` discount drives its evidence to ≈0: it must NOT
#: over-merge two distinct agents that happen to share it.
_POPULAR_JA4 = "t13d1516h2_POPULARchrome_000000000000"


def _plant_hostile(add: _Adder) -> None:
    """TWO DISTINCT agents that SHARE one popular JA4 (the over-merge trap).

    This is the adversary's attempt to defeat fusion in the *opposite* direction
    from the shared-credential pair (h): instead of one credential hiding two
    agents, here a single low-entropy NETWORK fingerprint (a popular JA4 shared
    by stock browsers / curl-impersonate) is the only thing the two agents have
    in common on the network plane. A naive matcher that treats JA4 as an
    identity key would COLLAPSE them into one entity.

    Each agent carries its OWN identity-grade ``code_hash`` anchor (eBPF) and its
    OWN ``behavior_sig``; they agree ONLY on the popular JA4. The N5 over-merge
    bar must hold: the popular bridge contributes ≈0 evidence (its anonymity set
    is large because many other footprints carry it), the strong code-hash
    components fail to close transitively across the JA4 bridge, and the engine
    resolves TWO distinct entities — never one. Zero false-merge.

    To make the JA4 genuinely POPULAR in-corpus (so the anonymity-set discount is
    real, not asserted), a handful of unrelated decoy egress footprints also
    carry it. Those decoys are their own (non-agent / singleton) sightings and do
    NOT carry either hostile label, so they cannot satisfy the (m) coverage claim.
    """
    for name, code, sni in (
        ("hostile-shared-ja4-A", "ee55" * 16, "api.openai.com"),
        ("hostile-shared-ja4-B", "ff66" * 16, "api.anthropic.com"),
    ):
        add(
            "m",
            _inc(
                PlaneId.KERNEL_EBPF,
                keys={
                    "code_hash": code,
                    "syscall_graph_sig": f"scg-{name}",
                    "exec_id": f"E:{name}:1",
                    "binary_path": "/usr/bin/python3.12",
                },
                attrs={"binary": "python3.12"},
                truth="hostile-shared-ja4",
                admissibility=Admissibility.PROVEN,
                at_s=21,
            ),
            _inc(
                PlaneId.NETWORK_EGRESS,
                keys={
                    "code_hash": code,         # identity-grade join to its OWN eBPF leaf
                    "ja4": _POPULAR_JA4,        # the SHARED popular bridge (≈0 via N5)
                    "sni": sni,
                    "behavior_sig": f"bs-{name}",
                },
                attrs={"packetization_mode": "bundled"},
                truth="hostile-shared-ja4",
                admissibility=Admissibility.OBSERVED,
                at_s=22,
            ),
        )

    # Make the JA4 genuinely popular in-corpus so its anonymity set is large and
    # the N5 discount is MEASURED, not assumed. These decoys are unrelated
    # singletons; they carry NO hostile label, so they cannot be mistaken for the
    # two hostile agents and do not satisfy the (m) coverage claim.
    for n in range(8):
        add(
            "m",
            _inc(
                PlaneId.NETWORK_EGRESS,
                keys={
                    "ja4": _POPULAR_JA4,
                    "sni": f"crowd-{n}.example.com",
                    "egress_ip": f"198.51.100.{n}",
                    "behavior_sig": f"bs-ja4-crowd-{n}",
                },
                attrs={"packetization_mode": "1:1", "crowd": "true"},
                truth=f"ja4-crowd-{n}",
                admissibility=Admissibility.OBSERVED,
                at_s=23 + n,
            ),
        )


# ---------------------------------------------------------------------------
# File-sensor fixtures — drive the REAL sensors through run_planes.
# ---------------------------------------------------------------------------


def _write_file_fixtures(root: Path) -> dict[str, str]:
    """Write real same-shape fixtures + return the activating ``TEX_SIEVE_*`` env.

    These exercise the REAL file-reading sensors end-to-end (not the in-memory
    incidence path) so the proof shows the engine surfacing planted archetypes
    through the production sense path too:

      * eBPF (P9) — a Tetragon JSONL export carrying the laptop-local (a) exec.
      * network-egress (P1) — an OCSF flow fixture carrying the egress-only (d)
        outbound LLM call.
      * static supply-chain (P8) — a repo holding the static (g) agent def.
    """
    root.mkdir(parents=True, exist_ok=True)

    # eBPF fixture: the laptop-local (a) agent's exec + a file write kprobe.
    ebpf = root / "tetra.jsonl"
    code_a = "aa11" * 16
    ebpf_events = [
        {
            "time": "2026-05-01T12:00:01.000Z",
            "process_exec": {
                "process": {
                    "exec_id": "E:laptop:4471",
                    "pid": 4471,
                    "binary": "/usr/bin/python3.12",
                    "arguments": "-m localtool.main",
                    "parent_exec_id": "/sbin/init",
                    "binary_properties": {"file": {"hash": {"sha256": code_a}}},
                }
            },
        },
        {
            "time": "2026-05-01T12:00:02.000Z",
            "process_kprobe": {
                "function_name": "security_file_permission",
                "process": {
                    "exec_id": "E:laptop:4471",
                    "binary": "/usr/bin/python3.12",
                    "binary_properties": {"file": {"hash": {"sha256": code_a}}},
                },
                "args": [{"file_arg": {"path": "/local/scratch/out-9912.md"}}],
            },
        },
    ]
    ebpf.write_text("\n".join(json.dumps(e) for e in ebpf_events) + "\n", encoding="utf-8")

    # network-egress fixture: the egress-only (d) outbound LLM call.
    flow = root / "flows.json"
    flow_records = [
        {
            "source_workload": "egress-only-host",
            "ja4": "t13d1516h2_aaaaaa222222_cccccc333333",
            "ja4s": "t130200_1301_a56c5b993250",
            "sni": "api.openai.com",
            "asn": "AS13335",
            "egress_ip": "104.18.7.99",
            "h2_settings_hash": "akamai:1:65536;2:0;3:1000",
            "alpn": "h2",
            "first_seen": "2026-05-01T00:00:00Z",
            "last_seen": "2026-05-02T00:00:00Z",
            "connection_count": 40,
            "bytes_out": 120000,
            "record_sizes": [512, 488, 530, 502],
            "inter_arrival_ms": [1000, 1000, 1001, 999, 1000, 1000],
            "evidence_ref": "zeek/ssl.log:egress-only",
        }
    ]
    flow.write_text(json.dumps(flow_records), encoding="utf-8")

    # static supply-chain fixture: the static (g) pre-runtime agent definition.
    repo = root / "repo"
    (repo / "agents").mkdir(parents=True, exist_ok=True)
    (repo / "agents" / "nightly_reporter.py").write_text(
        "from langgraph.graph import StateGraph\n\n"
        "# agent: nightly_reporter\n"
        "def build_nightly_reporter():\n"
        "    g = StateGraph(dict)\n"
        "    # tools: fetch, summarize, email\n"
        "    return g.compile()\n",
        encoding="utf-8",
    )
    (repo / "agents" / "agent.toml").write_text(
        '[agent]\nname = "nightly_reporter"\nframework = "langgraph"\n'
        'tools = ["fetch", "summarize", "email"]\nrunning = false\n',
        encoding="utf-8",
    )

    return {
        "TEX_SIEVE_P9_EBPF": "1",
        "TEX_SIEVE_P9_EBPF_EVENTS": str(ebpf),
        "TEX_SIEVE_P1_JA4": "1",
        "TEX_SIEVE_P1_FLOW_FIXTURE": str(flow),
        "TEX_SIEVE_P8_SUPPLY": "1",
        "TEX_SIEVE_P8_REPO": str(repo),
    }


# ---------------------------------------------------------------------------
# run_full_engine — the verifier's single entrypoint over the plants.
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class EngineResult:
    """The full-engine output over a planted estate.

    - ``entities``        — resolved ``SieveEntity`` set from the in-memory plants.
    - ``unseen``          — the calibrated ``UnseenEstimate`` (lower+CI+blind spots).
    - ``planes_result``   — the ``run_planes`` result over the file-sensor fixtures
                            (``None`` if the estate planted in-memory only).
    - ``estate``          — the estate that produced this result.
    """

    entities: tuple[SieveEntity, ...]
    unseen: UnseenEstimate
    planes_result: PlanesResult | None
    estate: PlantedEstate

    # -- convenience views the verifier asserts against --------------------

    def truths_of(self, entity: SieveEntity) -> set[str]:
        by_id = {i.incidence_id: i for i in self.estate.incidences}
        return {
            truth_of(by_id[mid]) for mid in entity.incidences if mid in by_id
        }

    def entities_with_truth(self, label: str) -> list[SieveEntity]:
        return [e for e in self.entities if label in self.truths_of(e)]

    def found_labels(self) -> set[str]:
        labels: set[str] = set()
        for e in self.entities:
            labels |= self.truths_of(e)
        return labels

    def blind_spot_planes(self) -> set[PlaneId]:
        return {b.missing_plane for b in self.unseen.named_blind_spots}


def run_full_engine(planted: PlantedEstate) -> EngineResult:
    """Run the FULL SIEVE brain over a planted estate.

    1. ``resolve_full`` over the in-memory incidences → the cross-plane fused
       entity set (FUSE + N1 split + agent-vs-human + capability + N4 incoherence).
    2. ``estimate_unseen`` over the resolved entities → the lower-bound+CI unseen
       estimate with a NAMED blind spot per withheld plane (the air-gapped (k)
       vantage is always withheld so it is named, never fake-found).
    3. (optional) ``run_planes`` over the file-sensor fixtures so the REAL
       sensors also surface their planted archetypes through the production path.

    NEVER mutates the real fleet. Pure over the planted estate.
    """
    entities = resolve_full(planted.incidences)

    # The capture occasions are the planes the planted entities were genuinely
    # seen on — count them so the estimate is over real vantages.
    seen_planes: set[PlaneId] = set()
    for e in entities:
        seen_planes |= e.planes_seen
    occasions = tuple(p for p in planted.occasions if p in seen_planes) or planted.occasions

    unseen = estimate_unseen(
        entities,
        occasions=occasions,
        withheld_planes=planted.withheld_planes,
    )

    planes_result: PlanesResult | None = None
    if planted.fixture_root is not None and planted.plane_env:
        planes_result = run_planes(
            env=planted.plane_env,
            context=SenseContext(),
            withheld_planes=planted.withheld_planes,
        )

    return EngineResult(
        entities=tuple(entities),
        unseen=unseen,
        planes_result=planes_result,
        estate=planted,
    )


# ---------------------------------------------------------------------------
# mutate — rename / restart / change egress / strip identity / move to stdio.
# ---------------------------------------------------------------------------


def mutate(incidences: Iterable[Incidence], *, kind: str = "all") -> list[Incidence]:
    """Return a MUTATED copy of a set of planted incidences.

    The mutations force the naive matcher to MISS while the two-axis identity
    (code-hash MERGE / behavior SPLIT) and cross-plane fusion survive:

      * ``rename``         — change the self-asserted name / pdp_agent_id (a
                             forgeable label). Identity must NOT depend on it.
      * ``restart``        — new ``exec_id`` (every re-exec mints a new id) while
                             ``code_hash`` + ``syscall_graph_sig`` are unchanged.
      * ``change_egress``  — new egress_ip / ja4 (rotated TLS). The behavioral /
                             code-hash join must still fuse the agent.
      * ``strip_identity`` — drop the directory ``oidc_sub`` / ``sp_object_id``
                             (credential rotation), keeping the behavioral anchor.
      * ``to_stdio``       — flip a network transport to stdio (a socket → stdio
                             move) keeping ``code_hash`` so eBPF still sees it.
      * ``all``            — apply every mutation that is meaningful per leaf.

    The ground-truth label (``raw_evidence_ref``) is PRESERVED so a re-run can
    check the same agent still fuses to the same logical identity after mutation.
    """
    out: list[Incidence] = []
    for inc in incidences:
        keys = inc.footprint.keys_dict()
        attrs = {k: v for k, v in inc.footprint.attrs}

        if kind in ("rename", "all"):
            for nm in ("agent_external_id", "pdp_agent_id"):
                if nm in keys:
                    keys[nm] = keys[nm] + "-renamed"
        if kind in ("restart", "all"):
            if "exec_id" in keys:
                keys["exec_id"] = keys["exec_id"] + ":restarted"
        if kind in ("change_egress", "all"):
            if "egress_ip" in keys:
                keys["egress_ip"] = "203.0.113.77"
            if "ja4" in keys:
                keys["ja4"] = "t13d1516h2_rotated_" + (keys.get("ja4", "")[-12:] or "x")
        if kind in ("strip_identity", "all"):
            for nm in ("oidc_sub", "sp_object_id"):
                keys.pop(nm, None)
        if kind in ("to_stdio", "all"):
            if "sni" in keys or attrs.get("packetization_mode"):
                attrs["transport"] = "stdio"

        new_fp = FootprintVector.of(inc.plane_id, keys=keys, attrs=attrs)
        out.append(
            Incidence(
                plane_id=inc.plane_id,
                footprint=new_fp,
                catchability=inc.catchability,
                admissibility=inc.admissibility,
                raw_evidence_ref=inc.raw_evidence_ref,  # preserve ground truth
                observed_at=inc.observed_at + timedelta(seconds=100),
            )
        )
    return out


def mutate_estate(planted: PlantedEstate, *, kind: str = "all") -> PlantedEstate:
    """A whole-estate mutation: rebuild an estate with every plant mutated.

    Preserves the archetype provenance map (keyed by ground-truth label) so a
    verifier can re-run ``run_full_engine`` and assert the same archetypes still
    resolve to the same entity COUNT after the mutation forced naive misses.
    """
    # Map each old incidence id -> its archetype key so we can rebuild the map.
    id_to_key: dict[UUID, str] = {}
    for key, ids in planted.by_archetype.items():
        for i in ids:
            id_to_key[i] = key

    old_by_id = {i.incidence_id: i for i in planted.incidences}
    mutated = mutate(planted.incidences, kind=kind)

    new_estate = PlantedEstate(
        occasions=planted.occasions,
        withheld_planes=planted.withheld_planes,
        irreducible_label=planted.irreducible_label,
    )
    # mutate() preserves order, so zip old->new to carry the archetype key.
    for old, new in zip(planted.incidences, mutated):
        key = id_to_key.get(old.incidence_id, "?")
        new_estate.incidences.append(new)
        new_estate.by_archetype.setdefault(key, []).append(new.incidence_id)
    assert len(old_by_id) == len(new_estate.incidences)
    return new_estate


# ---------------------------------------------------------------------------
# Real-fleet read-only context (the hard case on real data).
# ---------------------------------------------------------------------------


def real_fleet_available() -> bool:
    """True iff the real tex-enterprise fleet logs + workspace exist (read-only)."""
    try:
        return REAL_FLEET_LOGS.is_dir() and REAL_FLEET_WORKSPACE.is_dir()
    except OSError:
        return False


def real_fleet_context() -> SenseContext:
    """A ``SenseContext`` pointed READ-ONLY at the real fleet logs + workspace.

    Feed it to ``ActionsTrailSensor`` / ``FsWriteScanSensor`` (or
    ``pipeline.run_slice``) to demonstrate the gate-bypass case on REAL data. The
    sensors only READ; nothing here writes to the fleet.
    """
    return SenseContext(
        actions_dir=REAL_FLEET_LOGS,
        workspace_dir=REAL_FLEET_WORKSPACE,
    )


@dataclass(frozen=True)
class RealFleetSlice:
    """A BOUNDED read-only resolution over the REAL tex-enterprise fleet.

    Running ``resolve_full`` over the WHOLE fleet (~84k incidences) is an
    O(n²)-blocking pass; the verifier does not need totality to prove the hard
    case on real data — it needs to show the engine surfaces a REAL gate-bypass
    shadow (a file on disk with NO trail row) from the filesystem alone, with no
    cooperation from the agent. This slice does exactly that on a bounded, fast
    sample: every genuine gate-bypass FS leaf plus a sample of claimed/trail
    leaves for context.

    - ``bypass_count``   — number of REAL gate-bypass files (no trail row).
    - ``claimed_count``  — number of REAL files joined to a trail row.
    - ``entities``       — entities resolved over the bounded sample.
    - ``bypass_entities``— entities carrying at least one real gate-bypass leaf
                           (the shadow the engine surfaced read-only).
    """

    bypass_count: int
    claimed_count: int
    entities: tuple[SieveEntity, ...]
    bypass_entities: tuple[SieveEntity, ...]


def run_real_fleet_slice(sample_per_plane: int = 200) -> RealFleetSlice:
    """Resolve a BOUNDED read-only slice of the REAL fleet (the hard case live).

    Reads (never writes) the real fleet via ``ActionsTrailSensor`` +
    ``FsWriteScanSensor``, then fuses every genuine gate-bypass FS leaf together
    with a bounded sample of claimed-file + trail leaves so the pass is fast and
    deterministic. Returns a ``RealFleetSlice`` proving the engine surfaces real
    gate-bypassing shadows from the filesystem alone.
    """
    from tex.discovery.engine.sensors.actions_trail import ActionsTrailSensor
    from tex.discovery.engine.sensors.fs_write_scan import FsWriteScanSensor

    ctx = real_fleet_context()
    trail = list(ActionsTrailSensor().sense(ctx))
    fs = list(FsWriteScanSensor().sense(ctx))

    bypass = [i for i in fs if i.footprint.attr("gate_bypass") == "true"]
    claimed = [i for i in fs if i.footprint.attr("claimed") == "true"]

    sample = bypass + claimed[:sample_per_plane] + trail[:sample_per_plane]
    entities = resolve_full(sample)

    bypass_ids = {i.incidence_id for i in bypass}
    bypass_entities = tuple(e for e in entities if e.incidences & bypass_ids)

    return RealFleetSlice(
        bypass_count=len(bypass),
        claimed_count=len(claimed),
        entities=tuple(entities),
        bypass_entities=bypass_entities,
    )


@dataclass(frozen=True)
class FullEstateTiming:
    """A cold full-estate TIME-TO-FULL-ESTATE measurement on the REAL fleet.

    - ``incidences`` — total leaf incidences SENSE produced over the whole fleet.
    - ``entities``   — entities ``resolve_full`` resolved over ALL of them.
    - ``sense_s``    — wall-clock seconds for the SENSE stage (both sensors).
    - ``fuse_s``     — wall-clock seconds for FUSE (``resolve_full``: block + EM +
                       score + cluster + disambiguate + capability).
    - ``total_s``    — ``sense_s + fuse_s`` (the headline TIME-TO-FULL-ESTATE).
    """

    incidences: int
    entities: int
    sense_s: float
    fuse_s: float
    total_s: float


def run_real_fleet_full_estate() -> FullEstateTiming:
    """COLD-time the WHOLE real fleet through SENSE → FUSE (resolve_full).

    Unlike ``run_real_fleet_slice`` (a bounded sample), this runs the ENTIRE
    real tex-enterprise footprint (~10⁵ leaf incidences) through the full FUSE
    brain and measures the wall-clock TIME-TO-FULL-ESTATE. It backs the <60s
    speed target with a real, reproducible measurement on real data — read-only,
    never writing to the fleet. The engine must scale to the real leaf count
    (the star-blocking candidate generator + weighted-EM fit + behavioral-cohort
    cap), not just to the bounded sample.
    """
    import time

    from tex.discovery.engine.sensors.actions_trail import ActionsTrailSensor
    from tex.discovery.engine.sensors.fs_write_scan import FsWriteScanSensor

    ctx = real_fleet_context()
    t0 = time.perf_counter()
    incs: list[Incidence] = []
    incs.extend(ActionsTrailSensor().sense(ctx))
    incs.extend(FsWriteScanSensor().sense(ctx))
    sense_s = time.perf_counter() - t0

    t1 = time.perf_counter()
    entities = resolve_full(incs)
    fuse_s = time.perf_counter() - t1

    return FullEstateTiming(
        incidences=len(incs),
        entities=len(entities),
        sense_s=sense_s,
        fuse_s=fuse_s,
        total_s=sense_s + fuse_s,
    )


__all__ = [
    "Archetype",
    "archetypes",
    "archetype",
    "PlantedEstate",
    "plant_all",
    "EngineResult",
    "run_full_engine",
    "mutate",
    "mutate_estate",
    "truth_of",
    "real_fleet_available",
    "real_fleet_context",
    "RealFleetSlice",
    "run_real_fleet_slice",
    "FullEstateTiming",
    "run_real_fleet_full_estate",
    "REAL_FLEET_ROOT",
    "REAL_FLEET_LOGS",
    "REAL_FLEET_WORKSPACE",
]
