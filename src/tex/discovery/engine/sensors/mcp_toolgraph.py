"""
P10 — the MCP / A2A TOOL-GRAPH plane (``PlaneId.MCP_TOOLGRAPH``).

The white-space premise (ARCHITECTURE.md §8 P10; RESEARCH_LOG.md §1 P10, §139):
**the tool-call graph IS an agent census.** Every agent that connects to an MCP
server, exercises a tool-DAG, publishes a ``.well-known`` AgentCard, or declares
A2A ``skills[]`` leaves a footprint on the tool-protocol layer. The set+sequence
of tools an entity exercises IS its capability profile, and a MinHash over the
tool names clusters deployments even when tools are renamed or near-duplicated
[AegisMCP, arXiv 2510.19462, 2025-10; Censys MCP census, 2026-04; A2A AgentCard
spec, LF 2025–2026; MCP server cards SEP-1649/1960].

Two evidence grades on one plane (ARCHITECTURE.md §4 admissibility ladder)
-------------------------------------------------------------------------
- **OBSERVED** — the EXERCISED tool-call DAG: an MCP server's connected-client
  list (each client + the tools it has actually CALLED) and OTel/JSON-RPC tool
  spans. Admissibility ``OBSERVED`` — we watched the behavior.
- **CLAIMED** — the DECLARED surface: a ``.well-known`` / AgentCard endpoint's
  ``skills[]`` and an MCP server's ``tools/list`` advertisement. Admissibility
  ``CLAIMED`` — the agent declared it; a claim only, never load-bearing alone.

The declared-vs-exercised DELTA across these two grades is exactly the honesty
signal §4 surfaces (a tool exercised but never declared = hidden blast radius; a
tool declared but never exercised = dormant latent risk). This sensor emits BOTH
grades as separate incidences so the capability mapper can compute that delta.

The cross-plane fusion keys (what ``fuse.py`` links / splits on)
---------------------------------------------------------------
- ``tool_set_minhash`` — IDENTITY-grade (``fuse._IDENTITY_KEYS``). A MinHash over
  the agent's tool set is a behavioral deployment fingerprint: two sightings of
  the same agent (one on this plane, one on KERNEL_EBPF via ``syscall_graph_sig``,
  one on GOVERNANCE_STREAM via ``agent_external_id``) that share a tool-set
  MinHash fuse to ONE entity. MinHash (not a flat SHA256) so a renamed or
  near-duplicate tool-set still collides on enough bands to cluster.
- ``agent_external_id`` — IDENTITY-grade. When the MCP client / AgentCard carries
  a stable agent handle, it is the same join key the other planes emit, so the
  same agent's MCP footprint fuses to its trail/fs/governance footprints.
- ``mcp_server_url`` / ``agent_card_id`` — BRIDGING-grade (``fuse._BRIDGING_KEYS``).
  Many distinct agents share one MCP server URL; it links (a cohort) but never
  merges alone, and a single server collapsing k agents is the positive N1
  shared-credential split signal rather than an over-merge.
- ``a2a_skills`` — carried as a descriptive attr (the declared skill list) for
  receipts + capability mapping; it is not a match key.

PASSIVE vs ACTIVE (both real; active is opt-in + bounded)
---------------------------------------------------------
- PASSIVE (default): ingest a **configurable source** of MCP server records —
  each a server with its connected-client list (client + exercised ``tool_names``)
  and/or a declared ``tools`` advertisement — exactly the
  ``slack_live``/``openai_live``/``governance_stream`` pattern of wrapping a real
  connector as a SIGNAL SOURCE behind the sensor. The source is any zero-argument
  callable returning an iterable of server-record mappings (or such an iterable
  directly), e.g. ``MCPServerConnector`` re-used as the source. With NO source the
  sensor degrades to EMPTY.
- ACTIVE (opt-in, OFF by default): crawl a configured list of agent endpoints'
  ``.well-known/agent.json`` / AgentCard + A2A ``skills[]`` (a CLAIMED surface),
  and — separately gated — probe a configured list of MCP server URLs for
  ``tools/list`` (a CLAIMED surface). Active probing is bounded (a fixed endpoint
  list, a per-request timeout, a capped count) and uses an INJECTABLE fetcher so
  tests drive it with a recorded fixture of the SAME response shape — never a fake
  that pretends to be the network. With no fetcher / no endpoints it degrades to
  EMPTY.

Catchability is an ASSERTED plane recall (a slice constant): an agent that
connects to an instrumented MCP server or publishes an AgentCard is seen with
near-certainty; agents that use no MCP server and publish no card are
out-of-cohort and are the estimator's job (named in the blind-spot ledger), not
faked here. The count-based slice estimator carries-but-does-not-consume this.

Flag-gating + degrade-to-empty (the non-negotiable default-safe contract)
-------------------------------------------------------------------------
Built only behind ``TEX_SIEVE_P10_MCP`` (ARCHITECTURE.md §8 table). The registry
env-built factory is INERT (no source, no active fetcher) so enabling the flag
without wiring a passive source / active endpoints senses NOTHING and never
raises. Active crawling is *additionally* gated behind ``TEX_SIEVE_P10_ACTIVE``
and active MCP ``tools/list`` probing behind ``TEX_SIEVE_P10_PROBE`` so the
network-touching paths stay OFF unless explicitly opted in. A missing source, a
raising callable, a malformed row, an unreachable endpoint — all degrade to
*fewer incidences*, never an exception.

References: ARCHITECTURE.md §4 (admissibility ladder), §8 (P10 flag table), §11
(vantage independence); RESEARCH_LOG.md §1 P10, §139 (MinHash deployment
fingerprint).
"""

from __future__ import annotations

import hashlib
import logging
from datetime import UTC, datetime
from typing import Callable, Iterable, Iterator, Mapping, Sequence

from tex.discovery.engine.models import (
    Admissibility,
    FootprintField,
    FootprintVector,
    Incidence,
    PlaneId,
)
from tex.discovery.engine.sensors.base import SenseContext

_logger = logging.getLogger(__name__)

#: ASSERTED recall of the MCP/tool-graph plane over MCP-connecting / card-publishing
#: agents (a slice constant, NOT measured; measurement deferred to Phase 5). An
#: agent that connects to an instrumented MCP server or publishes an AgentCard is
#: seen with near-certainty; agents that touch no tool-protocol surface are
#: out-of-cohort and surfaced by the estimator's blind-spot ledger, not faked here.
MCP_TOOLGRAPH_CATCHABILITY = 1.0

#: Number of MinHash permutations (bands). 32 short SHA-derived hashes over the
#: tool-name shingle set give a stable Jaccard estimate while staying compact
#: enough to live in a footprint key. The signature is the concatenation of the
#: per-permutation minima, so near-duplicate tool sets share most bands and a few
#: renamed tools shift only a few — they still cluster (RESEARCH_LOG §139).
_MINHASH_PERMUTATIONS = 32

#: A passive source of MCP server records: an iterable of server-record mappings,
#: or a zero-argument callable returning one (e.g. a ``MCPServerConnector`` whose
#: scan output is adapted to plain mappings). ``None`` → degrade empty.
ServerSource = (
    Callable[[], Iterable[Mapping[str, object]]]
    | Iterable[Mapping[str, object]]
    | None
)

#: An active fetcher: given a URL, returns the parsed JSON body as a mapping (an
#: AgentCard / ``.well-known/agent.json`` / ``tools/list`` response), or ``None``
#: when the endpoint is unreachable / malformed. INJECTABLE so tests drive it with
#: a recorded fixture of the SAME response shape; a live deployment passes a
#: bounded urllib fetcher. ``None`` → no active crawl.
ActiveFetcher = Callable[[str], Mapping[str, object] | None] | None

# --- field aliases (the vocabulary the real rails emit) --------------------
_SERVER_URL_ALIASES: tuple[str, ...] = ("server_url", "url", "endpoint", "mcp_server_url")
_SERVER_NAME_ALIASES: tuple[str, ...] = ("server_name", "name", "server")
_CLIENTS_ALIASES: tuple[str, ...] = ("clients", "connected_clients", "sessions")
_CLIENT_ID_ALIASES: tuple[str, ...] = ("client_id", "agent_external_id", "client_name", "name")
_CLIENT_NAME_ALIASES: tuple[str, ...] = ("client_name", "name", "client_id")
_EXERCISED_TOOLS_ALIASES: tuple[str, ...] = ("tool_names", "tools_called", "exercised_tools", "tool_calls")
_DECLARED_TOOLS_ALIASES: tuple[str, ...] = ("tools", "tools_list", "declared_tools", "advertised_tools")
_SKILLS_ALIASES: tuple[str, ...] = ("skills", "a2a_skills", "capabilities")
_CARD_ID_ALIASES: tuple[str, ...] = ("agent_card_id", "card_id", "agentId", "agent_id", "id")
_LAST_SEEN_ALIASES: tuple[str, ...] = ("last_seen_at", "last_seen", "ts", "timestamp")


def _first(row: Mapping[str, object], names: Sequence[str]) -> object | None:
    """First present, non-empty value among ``names`` (alias resolution)."""
    for name in names:
        if name in row:
            val = row[name]
            if val is not None and not (isinstance(val, str) and not val.strip()):
                return val
    return None


def _as_str(val: object | None) -> str | None:
    """Coerce a present value to a trimmed string, or ``None``."""
    if val is None:
        return None
    s = str(val).strip()
    return s or None


def _as_tool_list(val: object | None) -> list[str]:
    """Coerce a tool/skill payload into a sorted, deduped list of tool names.

    Accepts a list of strings, a list of mappings carrying a ``name``/``id``
    field (the AgentCard ``skills[]`` / MCP ``tools[]`` shape), or a single
    string. Anything else degrades to an empty list (never raises).
    """
    out: set[str] = set()
    if val is None:
        return []
    if isinstance(val, str):
        s = val.strip()
        return [s] if s else []
    if isinstance(val, Mapping):
        val = list(val.values())
    try:
        items = list(val)  # type: ignore[arg-type]
    except TypeError:
        return []
    for item in items:
        if isinstance(item, str):
            s = item.strip()
            if s:
                out.add(s)
        elif isinstance(item, Mapping):
            name = _as_str(_first(item, ("name", "id", "tool_name", "skill")))
            if name:
                out.add(name)
    return sorted(out)


def _coerce_observed_at(val: object | None) -> datetime:
    """tz-aware sighting time from epoch seconds / ISO string; now(UTC) fallback."""
    if val is None:
        return datetime.now(UTC)
    if isinstance(val, (int, float)) and not isinstance(val, bool):
        try:
            return datetime.fromtimestamp(float(val), tz=UTC)
        except (ValueError, OverflowError, OSError):
            return datetime.now(UTC)
    if isinstance(val, str):
        s = val.strip()
        # numeric string?
        try:
            return datetime.fromtimestamp(float(s), tz=UTC)
        except ValueError:
            pass
        try:
            dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
            return dt if dt.tzinfo is not None else dt.replace(tzinfo=UTC)
        except ValueError:
            return datetime.now(UTC)
    return datetime.now(UTC)


def tool_set_minhash(tools: Iterable[str], *, permutations: int = _MINHASH_PERMUTATIONS) -> str | None:
    """Compute a deterministic MinHash signature over a tool-name set.

    The set+sequence of tools an entity exercises IS its capability profile; a
    MinHash over the tool names is a deployment fingerprint that survives renames
    and near-duplication better than a flat SHA256 (RESEARCH_LOG §139). We shingle
    each tool name into character-trigrams (so ``send_email`` and ``send_emails``
    still share most shingles), then take ``permutations`` salted-SHA256 minima
    over the shingle universe and concatenate the per-permutation minima into one
    stable hex signature.

    Returns ``None`` for an empty tool set (an agent with no tools has no
    tool-set fingerprint — it is NOT silently fingerprinted as the empty agent).
    Pure, deterministic, no external dependency.
    """
    names = sorted({t.strip().casefold() for t in tools if isinstance(t, str) and t.strip()})
    if not names:
        return None
    # Shingle every tool name into char-trigrams so near-duplicates overlap.
    shingles: set[str] = set()
    for name in names:
        padded = f"^{name}$"
        if len(padded) <= 3:
            shingles.add(padded)
        else:
            for i in range(len(padded) - 2):
                shingles.add(padded[i : i + 3])
    if not shingles:
        return None
    minima: list[str] = []
    for perm in range(permutations):
        salt = perm.to_bytes(2, "big")
        best: str | None = None
        for sh in shingles:
            h = hashlib.sha256(salt + sh.encode("utf-8")).hexdigest()[:8]
            if best is None or h < best:
                best = h
        minima.append(best or "00000000")
    return hashlib.sha256("".join(minima).encode("ascii")).hexdigest()


class MCPToolGraphSensor:
    """Emits MCP/tool-graph incidences (P10) — OBSERVED tool-DAG ∩ CLAIMED card.

    Construct with:

    - ``source`` — a PASSIVE configurable source of MCP server records (an
      iterable of server-record mappings or a zero-arg callable returning one),
      the ``slack_live``/``governance_stream`` pattern of wrapping a real
      connector as a SIGNAL SOURCE. Each record is a server with its
      connected-client list (each client + the tools it has CALLED) and/or a
      declared ``tools`` advertisement. ``None`` (default) → no passive ingest.
    - ``active_endpoints`` — an OPT-IN, bounded list of agent endpoints whose
      ``.well-known``/AgentCard + A2A ``skills[]`` to crawl (a CLAIMED surface).
    - ``probe_servers`` — an OPT-IN, bounded list of MCP server URLs to probe for
      ``tools/list`` (a CLAIMED surface). Separate from ``active_endpoints`` so
      MCP probing can be enabled independently.
    - ``fetcher`` — an INJECTABLE active fetcher (URL → parsed-JSON-mapping or
      ``None``). Required for any active crawl; ``None`` → no active crawl at all,
      even if endpoints are configured. Tests pass a fixture fetcher; a live
      deployment passes a bounded urllib fetcher.
    - ``max_active`` — a hard cap on the number of active endpoint fetches so the
      crawl is bounded regardless of list length.

    With ``source=None`` and no active fetcher the sensor degrades to EMPTY: it
    senses nothing and never raises. ``sense`` ignores ``SenseContext`` (the MCP
    source is supplied at construction) but accepts it to satisfy ``EngineSensor``.
    """

    plane_id: PlaneId = PlaneId.MCP_TOOLGRAPH

    def __init__(
        self,
        source: ServerSource = None,
        *,
        active_endpoints: Sequence[str] | None = None,
        probe_servers: Sequence[str] | None = None,
        fetcher: ActiveFetcher = None,
        catchability: float = MCP_TOOLGRAPH_CATCHABILITY,
        max_active: int = 64,
    ) -> None:
        self._source = source
        self._active_endpoints = tuple(active_endpoints or ())
        self._probe_servers = tuple(probe_servers or ())
        self._fetcher = fetcher
        self._catchability = catchability
        self._max_active = max(0, int(max_active))

    # ------------------------------------------------------------------
    # public
    # ------------------------------------------------------------------

    def sense(self, context: SenseContext) -> Iterable[Incidence]:  # noqa: ARG002
        """Project the configured passive source + opt-in active crawl into
        ``Incidence`` records.

        - PASSIVE: for each server record, emit one OBSERVED incidence per
          connected client keyed on ``{tool_set_minhash, agent_external_id?,
          mcp_server_url, agent_card_id?}`` with the exercised tool set; emit one
          CLAIMED incidence per server-level ``tools/list`` declaration.
        - ACTIVE (opt-in, only if a ``fetcher`` is wired): crawl each configured
          endpoint's AgentCard / ``.well-known`` (CLAIMED ``skills[]`` →
          ``a2a_skills`` + ``tool_set_minhash``) and probe each configured MCP
          server URL for ``tools/list`` (CLAIMED).
        - Returns an empty iterable on a missing/unreadable/empty source and no
          wired fetcher. NEVER raises.
        """
        return list(self._iter())

    # ------------------------------------------------------------------
    # internals — passive
    # ------------------------------------------------------------------

    def _iter(self) -> Iterator[Incidence]:
        yield from self._passive_incidences()
        yield from self._active_incidences()

    def _resolve_rows(self) -> list[Mapping[str, object]]:
        """Materialize the configured passive source into server-record mappings.

        Degrades to ``[]`` on a missing source, a callable that raises, a
        non-iterable result, or rows that are not mappings (skipped). Never raises.
        """
        source = self._source
        if source is None:
            return []
        try:
            raw = source() if callable(source) else source
        except Exception as exc:  # noqa: BLE001 — degrade-to-empty is the contract
            _logger.info("sieve: mcp-toolgraph source raised, degrading empty: %s", exc)
            return []
        rows: list[Mapping[str, object]] = []
        try:
            for item in raw:  # type: ignore[union-attr]
                if isinstance(item, Mapping):
                    rows.append(item)
        except TypeError:
            return []
        except Exception as exc:  # noqa: BLE001 — a lazy iterator that faults mid-stream
            _logger.info("sieve: mcp-toolgraph iteration faulted: %s", exc)
            return rows
        return rows

    def _passive_incidences(self) -> Iterator[Incidence]:
        rows = self._resolve_rows()
        for s_idx, server in enumerate(rows):
            server_url = _as_str(_first(server, _SERVER_URL_ALIASES))
            server_name = _as_str(_first(server, _SERVER_NAME_ALIASES))
            # A server with no URL and no name carries no locatable footprint.
            server_handle = server_url or server_name
            if server_handle is None:
                # Still allow client-only records (server identity unknown) only
                # if the clients carry their own card id; otherwise skip.
                pass

            clients = _first(server, _CLIENTS_ALIASES)
            client_list: list[Mapping[str, object]] = []
            if isinstance(clients, (list, tuple)):
                client_list = [c for c in clients if isinstance(c, Mapping)]

            for c_idx, client in enumerate(client_list):
                inc = self._client_incidence(
                    s_idx, c_idx, server_url, server_name, client
                )
                if inc is not None:
                    yield inc

            # Server-level DECLARED tools (an MCP tools/list advertisement carried
            # passively in the record) → a CLAIMED incidence for the server.
            declared = _as_tool_list(_first(server, _DECLARED_TOOLS_ALIASES))
            if declared and server_handle is not None:
                inc = self._declared_incidence(
                    s_idx,
                    server_url=server_url,
                    server_name=server_name,
                    card_id=_as_str(_first(server, _CARD_ID_ALIASES)),
                    declared_tools=declared,
                    skills=_as_tool_list(_first(server, _SKILLS_ALIASES)),
                    observed_at=_coerce_observed_at(_first(server, _LAST_SEEN_ALIASES)),
                    ref=f"mcp_server_tools_list:{server_handle}",
                )
                if inc is not None:
                    yield inc

    def _client_incidence(
        self,
        s_idx: int,
        c_idx: int,
        server_url: str | None,
        server_name: str | None,
        client: Mapping[str, object],
    ) -> Incidence | None:
        """One OBSERVED incidence for a connected MCP client's exercised tool-DAG."""
        exercised = _as_tool_list(_first(client, _EXERCISED_TOOLS_ALIASES))
        minhash = tool_set_minhash(exercised)
        external_id = _as_str(_first(client, _CLIENT_ID_ALIASES))
        card_id = _as_str(_first(client, _CARD_ID_ALIASES))

        keys: dict[str, str] = {}
        # IDENTITY-grade behavioral fingerprint (fuse._IDENTITY_KEYS).
        if minhash is not None:
            keys[FootprintField.TOOL_SET_MINHASH] = minhash
        # IDENTITY-grade cross-plane join key when the client carries a handle.
        if external_id is not None:
            keys["agent_external_id"] = external_id
        # BRIDGING-grade cohort keys (fuse._BRIDGING_KEYS): a shared server links a
        # cohort, the positive N1 split signal, but never merges alone.
        if server_url is not None:
            keys[FootprintField.MCP_SERVER_URL] = server_url
        if card_id is not None:
            keys[FootprintField.AGENT_CARD_ID] = card_id

        # An incidence must carry SOME locating/joining key.
        if not keys:
            return None

        attrs: dict[str, str] = {"surface": "exercised_tool_dag"}
        if server_name is not None:
            attrs["server_name"] = server_name
        if exercised:
            attrs[FootprintField.A2A_SKILLS] = ",".join(exercised)
            attrs["exercised_tools"] = ",".join(exercised)
        host_kind = _as_str(client.get("host_kind"))
        if host_kind is not None:
            attrs["host_kind"] = host_kind

        observed_at = _coerce_observed_at(_first(client, _LAST_SEEN_ALIASES))
        handle = external_id or card_id or server_url or server_name or f"{s_idx}"
        ref = f"mcp_client:{handle}:{c_idx}"
        return self._make(
            keys, attrs, Admissibility.OBSERVED, ref, observed_at
        )

    def _declared_incidence(
        self,
        s_idx: int,
        *,
        server_url: str | None,
        server_name: str | None,
        card_id: str | None,
        declared_tools: Sequence[str],
        skills: Sequence[str],
        observed_at: datetime,
        ref: str,
    ) -> Incidence | None:
        """One CLAIMED incidence for a DECLARED tool surface (tools/list / card)."""
        all_declared = sorted({*declared_tools, *skills})
        minhash = tool_set_minhash(all_declared)
        keys: dict[str, str] = {}
        if minhash is not None:
            keys[FootprintField.TOOL_SET_MINHASH] = minhash
        if server_url is not None:
            keys[FootprintField.MCP_SERVER_URL] = server_url
        if card_id is not None:
            keys[FootprintField.AGENT_CARD_ID] = card_id
        if not keys:
            return None

        attrs: dict[str, str] = {"surface": "declared_tools_list"}
        if server_name is not None:
            attrs["server_name"] = server_name
        if declared_tools:
            attrs["declared_tools"] = ",".join(declared_tools)
        if skills:
            attrs[FootprintField.A2A_SKILLS] = ",".join(skills)
        return self._make(
            keys, attrs, Admissibility.CLAIMED, ref, observed_at
        )

    # ------------------------------------------------------------------
    # internals — active (opt-in, bounded, injectable fetcher)
    # ------------------------------------------------------------------

    def _active_incidences(self) -> Iterator[Incidence]:
        """Crawl AgentCard/.well-known endpoints + probe MCP servers (opt-in).

        Requires a wired ``fetcher``; with none, no active crawl runs at all
        (the default-safe path). Bounded by ``max_active`` total fetches. Every
        fetch is wrapped so an unreachable endpoint / malformed body degrades to
        *fewer incidences*, never an exception.
        """
        fetcher = self._fetcher
        if fetcher is None:
            return
        if not (self._active_endpoints or self._probe_servers):
            return

        budget = self._max_active
        # AgentCard / .well-known crawl (A2A skills[] — CLAIMED).
        for url in self._active_endpoints:
            if budget <= 0:
                break
            budget -= 1
            inc = self._crawl_agent_card(fetcher, url)
            if inc is not None:
                yield inc

        # MCP server tools/list probe (CLAIMED).
        for url in self._probe_servers:
            if budget <= 0:
                break
            budget -= 1
            inc = self._probe_tools_list(fetcher, url)
            if inc is not None:
                yield inc

    def _safe_fetch(
        self, fetcher: Callable[[str], Mapping[str, object] | None], url: str
    ) -> Mapping[str, object] | None:
        """Invoke the fetcher, degrading any failure to ``None`` (never raises)."""
        try:
            body = fetcher(url)
        except Exception as exc:  # noqa: BLE001 — unreachable endpoint degrades empty
            _logger.info("sieve: mcp-toolgraph active fetch failed for %s: %s", url, exc)
            return None
        return body if isinstance(body, Mapping) else None

    def _crawl_agent_card(
        self, fetcher: Callable[[str], Mapping[str, object] | None], url: str
    ) -> Incidence | None:
        """Crawl one ``.well-known``/AgentCard endpoint → a CLAIMED incidence."""
        body = self._safe_fetch(fetcher, url)
        if body is None:
            return None
        skills = _as_tool_list(_first(body, _SKILLS_ALIASES))
        declared = _as_tool_list(_first(body, _DECLARED_TOOLS_ALIASES))
        all_skills = sorted({*skills, *declared})
        card_id = _as_str(_first(body, _CARD_ID_ALIASES))
        external_id = _as_str(_first(body, ("agent_external_id", "name")))
        minhash = tool_set_minhash(all_skills)

        keys: dict[str, str] = {}
        if minhash is not None:
            keys[FootprintField.TOOL_SET_MINHASH] = minhash
        if external_id is not None:
            keys["agent_external_id"] = external_id
        if card_id is not None:
            keys[FootprintField.AGENT_CARD_ID] = card_id
        keys[FootprintField.MCP_SERVER_URL] = url  # the crawled endpoint is a cohort key
        if minhash is None and external_id is None and card_id is None:
            # Nothing but the URL — not a discoverable agent footprint.
            return None

        attrs: dict[str, str] = {"surface": "agent_card", "endpoint": url}
        if all_skills:
            attrs[FootprintField.A2A_SKILLS] = ",".join(all_skills)
        return self._make(
            keys,
            attrs,
            Admissibility.CLAIMED,
            f"agent_card:{url}",
            _coerce_observed_at(_first(body, _LAST_SEEN_ALIASES)),
        )

    def _probe_tools_list(
        self, fetcher: Callable[[str], Mapping[str, object] | None], url: str
    ) -> Incidence | None:
        """Probe one MCP server URL for ``tools/list`` → a CLAIMED incidence."""
        body = self._safe_fetch(fetcher, url)
        if body is None:
            return None
        # MCP tools/list returns {"result": {"tools": [...]}} or a flat {"tools": [...]}.
        result = body.get("result")
        tools_payload: object | None = None
        if isinstance(result, Mapping):
            tools_payload = _first(result, _DECLARED_TOOLS_ALIASES)
        if tools_payload is None:
            tools_payload = _first(body, _DECLARED_TOOLS_ALIASES)
        declared = _as_tool_list(tools_payload)
        minhash = tool_set_minhash(declared)

        keys: dict[str, str] = {FootprintField.MCP_SERVER_URL: url}
        if minhash is not None:
            keys[FootprintField.TOOL_SET_MINHASH] = minhash
        card_id = _as_str(_first(body, _CARD_ID_ALIASES))
        if card_id is not None:
            keys[FootprintField.AGENT_CARD_ID] = card_id
        if minhash is None:
            # A server with no advertised tools → no tool footprint worth a leaf.
            return None

        attrs: dict[str, str] = {"surface": "tools_list_probe", "endpoint": url}
        if declared:
            attrs["declared_tools"] = ",".join(declared)
        return self._make(
            keys,
            attrs,
            Admissibility.CLAIMED,
            f"tools_list_probe:{url}",
            datetime.now(UTC),
        )

    # ------------------------------------------------------------------
    # shared
    # ------------------------------------------------------------------

    def _make(
        self,
        keys: Mapping[str, str],
        attrs: Mapping[str, str],
        admissibility: Admissibility,
        ref: str,
        observed_at: datetime,
    ) -> Incidence | None:
        """Build one incidence, dropping (never raising) on an invalid value."""
        footprint = FootprintVector.of(
            plane_id=PlaneId.MCP_TOOLGRAPH, keys=dict(keys), attrs=dict(attrs)
        )
        try:
            return Incidence(
                plane_id=PlaneId.MCP_TOOLGRAPH,
                footprint=footprint,
                catchability=self._catchability,
                admissibility=admissibility,
                raw_evidence_ref=ref,
                observed_at=observed_at,
            )
        except ValueError:
            return None


# ---------------------------------------------------------------------------
# registry factory
# ---------------------------------------------------------------------------


_TRUTHY = frozenset({"1", "true", "yes", "on", "enabled"})


def _is_truthy(env: Mapping[str, str], flag: str) -> bool:
    val = env.get(flag)
    return isinstance(val, str) and val.strip().casefold() in _TRUTHY


def _split_list(raw: str | None) -> tuple[str, ...]:
    """Parse a comma/whitespace-separated endpoint list from an env var."""
    if not raw:
        return ()
    parts = [p.strip() for chunk in raw.split(",") for p in chunk.split()]
    return tuple(p for p in parts if p)


def build_mcp_toolgraph_sensor(env: Mapping[str, str]) -> MCPToolGraphSensor:
    """Registry factory for the P10 MCP/tool-graph sensor (degrade-empty).

    The registry hands this the process ``env`` mapping. There is no PASSIVE
    source to construct from env alone — the MCP server-record source is an
    in-process hook wired at runtime by the host (``register_sensor`` with a
    configured instance wrapping ``MCPServerConnector`` or a live MCP inventory),
    so the env-built sensor has no passive source and senses nothing on that path.

    ACTIVE crawling is constructed ONLY when BOTH (a) its own opt-in flag is set
    AND (b) a fetcher could be built. The env-built factory deliberately wires NO
    network fetcher (a live deployment passes a bounded urllib fetcher via
    ``register_sensor``), so even with ``TEX_SIEVE_P10_ACTIVE`` /
    ``TEX_SIEVE_P10_PROBE`` set, the env-built sensor stays INERT — enabling
    ``TEX_SIEVE_P10_MCP`` without wiring a source/fetcher yields an empty plane,
    never a crash and never an un-opted-in network touch. The active endpoint
    lists are parsed here so a host that DOES wire a fetcher gets a bounded crawl.
    """
    active_on = _is_truthy(env, "TEX_SIEVE_P10_ACTIVE")
    probe_on = _is_truthy(env, "TEX_SIEVE_P10_PROBE")
    endpoints = _split_list(env.get("TEX_SIEVE_P10_ENDPOINTS")) if active_on else ()
    probes = _split_list(env.get("TEX_SIEVE_P10_PROBE_URLS")) if probe_on else ()
    return MCPToolGraphSensor(
        source=None,
        active_endpoints=endpoints,
        probe_servers=probes,
        fetcher=None,  # env-built factory wires NO network fetcher (default-safe)
    )


__all__ = [
    "MCPToolGraphSensor",
    "build_mcp_toolgraph_sensor",
    "tool_set_minhash",
    "MCP_TOOLGRAPH_CATCHABILITY",
    "ServerSource",
    "ActiveFetcher",
]
