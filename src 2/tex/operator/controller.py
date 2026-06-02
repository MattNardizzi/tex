"""
EnrollmentController — watches namespaces and keeps the EnrollmentScope true.

The core (``reconcile_event`` / ``resync``) is framework-agnostic and fully
testable without a cluster: feed it namespace events, it updates the scope.
The driver (``run``) is the thin Kubernetes glue — a list-then-watch loop over
namespaces using the official client. The driver is import-guarded so the
package loads (and the core tests run) without the kubernetes library present.
"""

from __future__ import annotations

import logging
import time
from typing import Any

from tex.operator.scope import EnrollmentScope

_logger = logging.getLogger("tex.operator.controller")

__all__ = ["EnrollmentController"]


class EnrollmentController:
    def __init__(self, scope: EnrollmentScope | None = None) -> None:
        self.scope = scope or EnrollmentScope()

    # ------------------------------------------------------------------ core

    def reconcile_event(self, event_type: str, namespace: str, labels: dict[str, str] | None) -> bool:
        """Apply one watch event. Returns True if the governed set changed.

        ``event_type`` is ADDED / MODIFIED / DELETED (Kubernetes watch verbs).
        """
        et = (event_type or "").upper()
        if et == "DELETED":
            changed = self.scope.remove_namespace(namespace)
        else:  # ADDED / MODIFIED — reconcile from current labels
            changed = self.scope.set_namespace(namespace, labels)
        if changed:
            _logger.info(
                "enrollment changed: ns=%s event=%s governed=%s",
                namespace, et, self.scope.is_governed(namespace),
            )
        return changed

    def resync(self, namespaces: dict[str, dict[str, str]]) -> None:
        """Full resync from a snapshot of {namespace: labels}."""
        self.scope.replace_all(namespaces)
        _logger.info("enrollment resync: %d governed namespace(s)", len(self.scope.snapshot()))

    # ------------------------------------------------------------------ driver

    def run(self, *, resync_seconds: int = 300) -> None:  # pragma: no cover (needs cluster)
        """List-then-watch namespaces forever, reconciling the scope.

        Runs in-cluster (ServiceAccount token) or against the local kubeconfig.
        Resilient: on watch expiry/error it re-lists and resumes.
        """
        try:
            from kubernetes import client, config, watch
        except Exception as exc:  # noqa: BLE001
            raise RuntimeError(
                "the 'kubernetes' package is required to run the controller; "
                "install tex with the [operator] extra"
            ) from exc

        try:
            config.load_incluster_config()
        except Exception:  # noqa: BLE001
            config.load_kube_config()

        v1 = client.CoreV1Api()

        def _labels(ns: Any) -> dict[str, str]:
            md = getattr(ns, "metadata", None)
            return dict(getattr(md, "labels", None) or {})

        def _name(ns: Any) -> str:
            md = getattr(ns, "metadata", None)
            return str(getattr(md, "name", "") or "")

        while True:
            try:
                listing = v1.list_namespace()
                self.resync({_name(ns): _labels(ns) for ns in listing.items})
                resource_version = listing.metadata.resource_version
                w = watch.Watch()
                last_resync = time.time()
                for event in w.stream(
                    v1.list_namespace,
                    resource_version=resource_version,
                    timeout_seconds=resync_seconds,
                ):
                    ns = event.get("object")
                    self.reconcile_event(event.get("type", ""), _name(ns), _labels(ns))
                    if time.time() - last_resync > resync_seconds:
                        break  # periodic re-list to heal any missed events
            except Exception as exc:  # noqa: BLE001
                _logger.warning("namespace watch error; re-listing in 3s: %s", exc)
                time.sleep(3)
