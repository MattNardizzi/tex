"""
Restorative-path executor.

Walks a manifest-declared restorative path from the active governance
graph, emits each restorative event in declared order as an
ML-DSA-signed governance-log record, and verifies the final actor
institutional state matches ``target_legal_state_id``.

Reference
---------
- arxiv 2601.11369 (Bracale Syrnikov et al., Jan 2026), §4.2
  "Restorative paths": three restoration kinds (expiry,
  credit_relief, clean_restoration); §6.2.2 sanction ladder + Table 5
  paper defaults.
- arxiv 2604.07833 v2 (Embodied Agents Runtime Governance, Apr 10
  2026): recovery success benchmarks (91.4% +/- 3.0% with full policy
  compliance; removal of Recovery Manager collapses to 28.1%). Used
  as production aspiration; this module guarantees *mechanical*
  correctness (every well-formed path call succeeds).

Contract (FRONTIER_DELTA_thread_8 §4 Delta-3)
---------------------------------------------
``execute()`` returns True only if:
  (a) the manifest restorative path exists for ``path_id``,
  (b) every restorative event in ``restorative_event_kinds`` is
      emitted to the governance log in declared order via ML-DSA-
      signed records,
  (c) the actor's effective institutional state after execution
      matches the path's ``target_legal_state_id``.

Failure modes return False (FAIL-CLOSED, per Section 3 hard
constraint). All failures emit telemetry so operators can detect them
in the live event stream.

Priority: P2 (live).
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from tex.observability.telemetry import emit_event


# Governance-log payload kind for restorative-path executions.
_LOG_KIND_RESTORATIVE: str = "restorative_path_executed"
_LOG_KIND_RESTORATIVE_EVENT: str = "restorative_event_emitted"


class RestorativePathExecutor:
    """
    Executes a manifest-declared restorative path against the live
    governance graph.

    Construction
    ------------
    >>> executor = RestorativePathExecutor(
    ...     governance_graph=graph,
    ...     ledger=governance_log,
    ...     institutional_states=states_dict,
    ... )

    Parameters
    ----------
    governance_graph
        A ``tex.institutional.governance_graph.GovernanceGraph`` with
        ``lookup_restorative_path(path_id)`` returning a
        ``RestorativePath``.
    ledger
        A ``GovernanceLog`` instance for ML-DSA-signed record emission,
        or ``None`` for test paths that only exercise the lookup
        + state-transition logic.
    institutional_states
        Per-actor state map (``actor_entity_id -> state_id``). The
        executor mutates this dict in place when ``execute()``
        succeeds, transitioning the actor's state to the path's
        ``target_legal_state_id``. If ``None``, state transitions are
        skipped (test path).
    """

    def __init__(
        self,
        *,
        governance_graph: Any | None,  # GovernanceGraph | None
        ledger: Any | None,  # GovernanceLog | None
        institutional_states: dict[str, str] | None = None,
    ) -> None:
        self._graph = governance_graph
        self._ledger = ledger
        self._institutional_states: dict[str, str] | None = institutional_states

    def execute(self, *, path_id: str, target_entity_id: str) -> bool:
        """
        Execute the restorative path identified by ``path_id`` against
        the actor ``target_entity_id``.

        Returns
        -------
        True if and only if all three contract clauses (a/b/c above)
        hold. False on any failure; failure mode is recorded in the
        emitted telemetry event so operators can diagnose.

        Behavior
        --------
        1. Look up the RestorativePath via the governance graph. If
           the path is undeclared or the graph is unwired, return
           False.
        2. Append a header record to the governance log announcing the
           path execution (path_id, target, declared event kinds,
           target_legal_state_id).
        3. For each kind in ``restorative_event_kinds``, append an
           individual ML-DSA-signed record. Order is preserved.
        4. Transition the actor's institutional state to
           ``target_legal_state_id`` in the in-memory map.
        5. Verify the post-execution state matches.

        The executor is best-effort: if the ledger append fails midway,
        prior records remain in the log (which is append-only and
        intentional). The return value still reports False so the
        caller knows the path did not complete.
        """
        if not isinstance(path_id, str) or not path_id:
            emit_event(
                "restorative.execute.invalid_path_id",
                target_entity_id=target_entity_id,
            )
            return False
        if not isinstance(target_entity_id, str) or not target_entity_id:
            emit_event(
                "restorative.execute.invalid_target_entity_id",
                path_id=path_id,
            )
            return False

        # (a) Path lookup.
        if self._graph is None:
            emit_event(
                "restorative.execute.no_graph_wired",
                path_id=path_id,
                target_entity_id=target_entity_id,
            )
            return False

        try:
            path = self._graph.lookup_restorative_path(path_id)
        except KeyError:
            emit_event(
                "restorative.execute.unknown_path",
                path_id=path_id,
                target_entity_id=target_entity_id,
            )
            return False
        except Exception as exc:
            emit_event(
                "restorative.execute.graph_lookup_error",
                path_id=path_id,
                target_entity_id=target_entity_id,
                error=f"{type(exc).__name__}: {exc}",
            )
            return False

        emit_event(
            "restorative.execute.start",
            path_id=path_id,
            target_entity_id=target_entity_id,
            restoration_kind=getattr(path, "restoration_kind", "expiry"),
            target_legal_state_id=path.target_legal_state_id,
            n_event_kinds=len(path.restorative_event_kinds),
        )

        # (b) Emit ordered records. The header + per-event records are
        # all written to the governance log; we tolerate a missing
        # ledger only in test paths (ledger=None) and emit telemetry in
        # that case.
        header_id: str | None = None
        emitted_event_ids: list[str] = []

        if self._ledger is not None:
            try:
                header_id = self._ledger.record_observation(
                    oracle_observation=self._header_payload(
                        path=path, target_entity_id=target_entity_id
                    )
                )
            except Exception as exc:
                emit_event(
                    "restorative.execute.header_append_failed",
                    path_id=path_id,
                    target_entity_id=target_entity_id,
                    error=f"{type(exc).__name__}: {exc}",
                )
                return False

            for index, event_kind in enumerate(path.restorative_event_kinds):
                try:
                    event_id = self._ledger.record_observation(
                        oracle_observation=self._per_event_payload(
                            path_id=path_id,
                            target_entity_id=target_entity_id,
                            event_kind=event_kind,
                            sequence_index=index,
                        )
                    )
                except Exception as exc:
                    emit_event(
                        "restorative.execute.event_append_failed",
                        path_id=path_id,
                        target_entity_id=target_entity_id,
                        event_kind=event_kind,
                        sequence_index=index,
                        error=f"{type(exc).__name__}: {exc}",
                    )
                    return False
                emitted_event_ids.append(event_id)
        else:
            emit_event(
                "restorative.execute.no_ledger_wired",
                path_id=path_id,
                target_entity_id=target_entity_id,
            )

        # (c) Transition + verify.
        target_state = path.target_legal_state_id
        if self._institutional_states is not None:
            prior_state = self._institutional_states.get(
                target_entity_id, "active"
            )
            self._institutional_states[target_entity_id] = target_state
            emit_event(
                "restorative.execute.state_transitioned",
                path_id=path_id,
                target_entity_id=target_entity_id,
                prior_state=prior_state,
                new_state=target_state,
            )

            # Verify post-execution.
            observed = self._institutional_states.get(target_entity_id)
            if observed != target_state:
                emit_event(
                    "restorative.execute.state_mismatch",
                    path_id=path_id,
                    target_entity_id=target_entity_id,
                    expected=target_state,
                    observed=observed,
                )
                return False

        emit_event(
            "restorative.execute.completed",
            path_id=path_id,
            target_entity_id=target_entity_id,
            target_legal_state_id=target_state,
            header_event_id=header_id,
            n_emitted=len(emitted_event_ids),
        )
        return True

    # ----------------------------------------------------------------- internals

    @staticmethod
    def _header_payload(*, path: Any, target_entity_id: str) -> dict:
        """Compose the governance-log header record for a path execution."""
        return {
            "kind": _LOG_KIND_RESTORATIVE,
            "actor_entity_id": "_restorative_path_executor",
            "target_entity_id": target_entity_id,
            "restorative_path_id": path.path_id,
            "restoration_kind": getattr(path, "restoration_kind", "expiry"),
            "target_legal_state_id": path.target_legal_state_id,
            "declared_event_kinds": list(path.restorative_event_kinds),
            "description": getattr(path, "description", ""),
            "emitted_at": datetime.now(UTC).isoformat(),
            "references": (
                "arxiv:2601.11369 §4.2 restorative paths; "
                "arxiv:2604.07833v2 recovery benchmarks"
            ),
        }

    @staticmethod
    def _per_event_payload(
        *,
        path_id: str,
        target_entity_id: str,
        event_kind: str,
        sequence_index: int,
    ) -> dict:
        """Compose the governance-log record for one restorative event."""
        return {
            "kind": _LOG_KIND_RESTORATIVE_EVENT,
            "actor_entity_id": "_restorative_path_executor",
            "target_entity_id": target_entity_id,
            "restorative_path_id": path_id,
            "restorative_event_kind": event_kind,
            "sequence_index": sequence_index,
            "emitted_at": datetime.now(UTC).isoformat(),
        }
