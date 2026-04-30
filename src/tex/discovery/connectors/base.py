"""
Connector framework for Tex's discovery layer.

A connector is a small adapter that knows how to query one platform
(Microsoft Graph, Salesforce, AWS Bedrock, GitHub, OpenAI, an MCP
server, etc.) and translate the platform's view of "AI agents that
exist here" into the canonical CandidateAgent shape declared in
tex.domain.discovery.

Connectors are not allowed to:

- mutate the agent registry directly
- write to the discovery ledger
- decide whether to promote a candidate to a real AgentIdentity

Those decisions belong to the reconciliation engine. A connector's
only job is "look at the platform, emit a sequence of CandidateAgent
records." That separation keeps connectors small, deterministic, and
testable in isolation.

This module ships:

- DiscoveryConnector: the runtime-checkable Protocol every connector
  must satisfy
- ConnectorContext: a tiny config object carrying the tenant_id and
  any per-run filters
- BaseConnector: a convenience abstract base class with normalization
  helpers most real connectors will want
- ConnectorError / ConnectorTimeout: typed errors for the engine to
  catch and turn into structured scan errors instead of crashes

Real production connectors that hit live APIs should implement async
versions; the engine handles both. For the in-repo connector library
we ship synchronous mock connectors that simulate the *shape* of
each platform's response without reaching outside the process. That
is the point of the architecture: when a customer hands you their
tenant credentials, you write the live connector against the same
Protocol and the entire reconciliation / ledger / fusion pipeline
keeps working unchanged.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Iterable, Protocol, runtime_checkable

from tex.domain.discovery import (
    CandidateAgent,
    DiscoverySource,
)


class ConnectorError(RuntimeError):
    """
    Raised when a connector cannot complete a scan because of a
    platform-side error (auth failure, rate limit, schema mismatch).

    The engine catches these and turns them into structured errors
    on the DiscoveryScanRun. They never escape into the request path
    of an evaluation, because discovery is decoupled from evaluation.
    """


class ConnectorTimeout(ConnectorError):
    """Raised when a connector exceeds its configured deadline."""


@dataclass(frozen=True, slots=True)
class ConnectorContext:
    """
    Per-run configuration handed to every connector.

    Filters are advisory: a connector that does not understand a
    filter is free to ignore it. The engine still applies the
    `tenant_id` filter on the engine side after the connector
    returns, so a connector that ignores it will not corrupt
    anything — it will just be slower.
    """

    tenant_id: str
    timeout_seconds: float = 30.0
    max_candidates: int = 5_000
    name_filter: str | None = None
    metadata: dict[str, str] = field(default_factory=dict)


@runtime_checkable
class DiscoveryConnector(Protocol):
    """
    The contract every connector implements.

    A connector exposes:

    - source: the DiscoverySource this connector reports under
    - name: a short, human-friendly id used in logs and the API
    - scan(context): the actual platform query

    `scan` returns an iterable of CandidateAgent records. Returning
    an iterator is allowed; the engine consumes it in one pass and
    the connector is free to release any resources it held.

    Connectors must be deterministic in the sense that "given the
    same platform state, scan returns the same records." This is
    what makes reconciliation idempotent.
    """

    source: DiscoverySource
    name: str

    def scan(self, context: ConnectorContext) -> Iterable[CandidateAgent]:
        """Run one scan and return the candidates found."""


class BaseConnector(ABC):
    """
    Convenience base for connectors that want a normalized shape.

    Subclasses implement `_run_scan` which returns the raw iterable.
    The base class enforces the `max_candidates` cap, the
    `name_filter` filter, and tenant-id propagation so the engine
    can rely on connectors emitting only well-formed candidates.
    """

    def __init__(self, *, source: DiscoverySource, name: str) -> None:
        self.source = source
        self.name = name

    def scan(self, context: ConnectorContext) -> Iterable[CandidateAgent]:
        produced = 0
        for candidate in self._run_scan(context):
            if context.tenant_id and candidate.tenant_id != context.tenant_id.casefold():
                # Should not happen with a well-behaved connector, but
                # the engine cannot assume connectors are well-behaved.
                continue
            if context.name_filter and not _name_matches(
                candidate.name, context.name_filter
            ):
                continue
            yield candidate
            produced += 1
            if produced >= context.max_candidates:
                return

    @abstractmethod
    def _run_scan(self, context: ConnectorContext) -> Iterable[CandidateAgent]:
        """Connector-specific scan logic."""


def _name_matches(name: str, filter_value: str) -> bool:
    """Case-insensitive contains check used by BaseConnector."""
    return filter_value.casefold() in name.casefold()
