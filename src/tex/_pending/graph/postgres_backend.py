"""
Postgres + pgvector temporal knowledge graph backend.

Schema sketch:

  entities      (id, kind, attrs jsonb, created_at, version)
  events        (id, kind, actor_id, target_id, payload jsonb, ts,
                 upstream_event_ids text[], crypto_receipt_id)
  entity_versions (entity_id, version, attrs_delta jsonb, ts)
  edges_by_kind (event_kind, actor_id, target_id, ts)  -- index helper

Plus pgvector embedding columns on entities + events for semantic
neighborhood queries.

Priority: P1.
"""

from __future__ import annotations


class PostgresTemporalKG:
    def __init__(self, *, dsn: str):
        self._dsn = dsn

    # TODO(P1): mirror in-memory API surface against Postgres tables
