"""
EnrollmentScope — the live source of truth for what is governed.

A namespace is governed iff it carries ``tex.systems/govern=enabled``. Its
tenant is ``tex.systems/tenant`` if present, else the namespace name. The
controller reconciles this set from the cluster; the webhook reads it to
decide whether to inject; the node agents poll it to decide which workloads
to redirect.

Thread-safe and snapshot-cheap: reads never block writes for long.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass

from tex.operator import GOVERN_ENABLED, GOVERN_LABEL, TENANT_LABEL

__all__ = ["GovernedNamespace", "EnrollmentScope"]


@dataclass(frozen=True, slots=True)
class GovernedNamespace:
    name: str
    tenant: str


def _tenant_for(namespace: str, labels: dict[str, str]) -> str:
    raw = (labels.get(TENANT_LABEL) or namespace or "").strip().casefold()
    return raw or namespace.strip().casefold()


def is_namespace_governed(labels: dict[str, str] | None) -> bool:
    if not labels:
        return False
    return (labels.get(GOVERN_LABEL) or "").strip().casefold() == GOVERN_ENABLED


class EnrollmentScope:
    """The governed set. namespace -> GovernedNamespace."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._governed: dict[str, GovernedNamespace] = {}

    def set_namespace(self, name: str, labels: dict[str, str] | None) -> bool:
        """Reconcile one namespace from its labels. Returns True if the
        governed set changed."""
        name = (name or "").strip()
        if not name:
            return False
        labels = labels or {}
        with self._lock:
            if is_namespace_governed(labels):
                gn = GovernedNamespace(name=name, tenant=_tenant_for(name, labels))
                changed = self._governed.get(name) != gn
                self._governed[name] = gn
                return changed
            existed = name in self._governed
            self._governed.pop(name, None)
            return existed

    def remove_namespace(self, name: str) -> bool:
        with self._lock:
            return self._governed.pop((name or "").strip(), None) is not None

    def replace_all(self, namespaces: dict[str, dict[str, str]]) -> None:
        """Full resync from a list of {namespace: labels}."""
        with self._lock:
            self._governed = {
                n: GovernedNamespace(name=n, tenant=_tenant_for(n, lbls))
                for n, lbls in namespaces.items()
                if is_namespace_governed(lbls)
            }

    def is_governed(self, namespace: str) -> bool:
        with self._lock:
            return (namespace or "").strip() in self._governed

    def tenant_for(self, namespace: str) -> str | None:
        with self._lock:
            gn = self._governed.get((namespace or "").strip())
            return gn.tenant if gn else None

    def snapshot(self) -> list[GovernedNamespace]:
        with self._lock:
            return sorted(self._governed.values(), key=lambda g: g.name)

    def to_jsonable(self) -> dict:
        items = self.snapshot()
        return {
            "namespaces": [{"name": g.name, "tenant": g.tenant} for g in items],
            "count": len(items),
        }
