"""The learning flywheel: sealed human resolutions → per-tenant conformal
calibration → a tighter DERIVED floor, with the honesty the statistics demand.

WHAT THIS WIRES
---------------
Session 2's DERIVED gate localizes the decisive step of an agent's action trace
with a conformal correctness floor (``tex.causal.conformal_attribution``). In
``calibrated`` mode it reads a held-out set of *true decisive-step* non-conformity
scores from the file named by ``TEX_CONFORMAL_CALIBRATION_PATH`` (one float per
line). This module produces that file from sealed human resolutions of held
decisions — so every confirmed resolution tightens the gate — WITHOUT touching
``conformal_attribution.py`` (which reads the env var at call time, in lane).

WHICH RESOLUTIONS FEED, AND WHY ONLY THOSE
------------------------------------------
The gate scores each trace step by ``ActionLedgerEntry.final_score`` ∈ [0,1], and
a ``Decision`` carries the same fused-risk ``final_score``. A calibration point
must be the score of a *confirmed-true* decisive error. Only a ``refused`` human
resolution supplies that: ``refused → was_safe=False`` (the mapping in
``tex.api.outcome_autoseal.map_resolution_to_outcome``), i.e. the operator
CONFIRMED the flagged action was the real failure. Its real ``final_score`` is the
calibration point.

  * ``approved`` (``was_safe=True``) is a FALSE alarm — feeding it would poison the
    "true decisive-step score" semantics the loader assumes.
  * ``held`` (``was_safe=None``) is unknown ground truth.

So they are EXCLUDED. The feed never INVENTS a score: it forwards the resolution's
own ``final_score`` unmodified, range-checked to [0,1], and writes nothing when one
is absent. It does NOT cryptographically prove the score came from a genuine sealed
``Decision`` — it trusts its caller. In the wired path the ``/decisions/{id}/seal``
handler passes the SERVER-LOOKED-UP ``Decision`` (from ``decision_store.get``), never
a request-body value, so a client cannot inject a chosen calibration point.

STRICT PER-TENANT — NO CROSS-CUSTOMER LEARNING
----------------------------------------------
There is no global calibration file. Each tenant gets its own ``{tenant}.scores``
file; the orchestrator points ``TEX_CONFORMAL_CALIBRATION_PATH`` at the requesting
tenant's file for the duration of that tenant's gate call. Tenant A's confirmed
errors never calibrate tenant B's floor.

HONEST COVERAGE LABEL — SELECTION-CONDITIONAL, NOT MARGINAL
----------------------------------------------------------
Split-conformal's finite-sample 1−α coverage assumes calibration and test scores
are exchangeable (i.i.d.). Human-resolved HELD decisions are NOT an i.i.d. draw —
they are the ambiguous tail the gate selected (``detail["dimension"]=="presence"``
holds). Under a data-dependent selection rule, marginal split-CP coverage
*provably* can fail (Jin & Ren, "Confidence on the Focal: Conformal Prediction
with Selection-Conditional Coverage", arXiv:2403.03868; cf. Barber et al.,
"Conformal prediction beyond exchangeability", Ann. Statist. 2023 — both retrieved
via this session's design survey). So the floor this feed earns is
**selection-conditional, per-tenant** — valid over the escalated/held population
the DERIVED gate actually fires on — NOT i.i.d. marginal coverage. That label is
written into the provenance sidecar next to every scores file. A minimum-n floor
keeps a handful of labels from masquerading as a formal guarantee — but note this
floor is a WRITER-SIDE convention: this feed withholds the scores file below
``MIN_CALIBRATION_N`` so the conformal loader finds nothing and stays transductive.
The conformal CONSUMER (``conformal_attribution``) performs NO n-check of its own —
it announces ``calibrated`` off ANY non-empty file at ``TEX_CONFORMAL_CALIBRATION_PATH``.
So the floor holds only as long as this feed is the sole producer of a tenant's
calibration path (which it is in the wired seam). A consumer-enforced floor would
need an n-gate inside ``conformal_attribution`` — out of this session's lane.

THE PROCESS-GLOBAL ENV TRAP (disclosed; primitive provided)
-----------------------------------------------------------
``TEX_CONFORMAL_CALIBRATION_PATH`` is a process-global env var. If one worker
serves two tenants concurrently, tenant A's ``os.environ`` set can race tenant B's
gate read → a cross-tenant calibration leak. :func:`tenant_calibration_env` is a
lock-guarded set/restore context manager the orchestrator MUST wrap the gate call
in; concurrent multi-tenant gate calls then serialize (single-flight per process).
A lock-free fix would require threading a per-call path into
``conformal_attribution`` — out of this session's lane.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import logging
import os
import re
import threading
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Iterator

_logger = logging.getLogger(__name__)

__all__ = [
    "MIN_CALIBRATION_N",
    "PRESENCE_ORIGIN_DIMENSION",
    "PresenceCalibrationFeed",
    "CalibrationResolution",
    "is_presence_origin_decision",
    "tenant_calibration_env",
    "calibration_disabled_env",
    "calibration_available",
    "default_calibration_feed",
    "record_resolution_for_calibration",
    "forget_resolution_for_calibration",
]

# Below this many confirmed labels, calibrated mode does NOT engage: the scores
# file is withheld so the loader returns None and the gate stays transductive.
# A small, selection-biased sample is the worst case for a false guarantee.
MIN_CALIBRATION_N: int = 30

_DEFAULT_DIR = "./data/presence_calibration"

# Serializes the process-global TEX_CONFORMAL_CALIBRATION_PATH env var across
# concurrent tenants in one process (see module docstring). RE-ENTRANT on purpose:
# the gate composes tenant_calibration_env with calibration_disabled_env, and a
# legacy caller may still wrap the gate in tenant_calibration_env — same-thread
# nesting must not self-deadlock. Cross-thread serialization (single-flight) is
# unchanged: a different thread still blocks until the owner fully releases.
_ENV_LOCK = threading.RLock()

# Per-path write locks so concurrent record/forget on one tenant serialize.
_PATH_LOCKS: dict[str, threading.Lock] = {}
_PATH_LOCKS_GUARD = threading.Lock()

_COVERAGE_SEMANTICS = (
    "selection-conditional, per-tenant — coverage over the escalated/held "
    "population the gate surfaces; NOT i.i.d. split-conformal marginal coverage "
    "(arXiv:2403.03868)"
)


def _safe_tenant(tenant: str) -> str:
    """Deterministic, collision-resistant, path-safe filename stem for a tenant.
    Keeps a readable slug + a short content hash so two tenants whose slugs collide
    after sanitization still get distinct files."""
    if not isinstance(tenant, str) or not tenant.strip():
        raise ValueError("calibration feed requires a non-empty tenant")
    slug = re.sub(r"[^A-Za-z0-9_.-]", "_", tenant)[:48]
    digest = hashlib.sha256(tenant.encode("utf-8")).hexdigest()[:12]
    return f"{slug}.{digest}"


def _path_lock(path: Path) -> threading.Lock:
    key = str(path)
    with _PATH_LOCKS_GUARD:
        lock = _PATH_LOCKS.get(key)
        if lock is None:
            lock = threading.Lock()
            _PATH_LOCKS[key] = lock
        return lock


def _extract(decision: Any, attr: str, default: Any = None) -> Any:
    if isinstance(decision, dict):
        return decision.get(attr, default)
    return getattr(decision, attr, default)


# The presence-origin marker the seal-route flywheel gates on. A presence ABSTAIN
# is raised as a tex.provenance.feed.HeldDecision tagged detail["dimension"]=="presence"
# (presence/gate/compose.py); the seal route, however, only ever resolves a
# governance tex.domain.decision.Decision (decision_store.get), which is
# frozen/extra="forbid" — so the ONLY place a presence-origin marker can ride is its
# one extensible field, ``metadata``. This constant names that mirrored marker.
PRESENCE_ORIGIN_DIMENSION = "presence"


def is_presence_origin_decision(decision: Any) -> bool:
    """True iff a governance ``Decision`` is PRESENCE-ORIGIN — i.e. it carries the
    presence-channel marker ``metadata["dimension"] == "presence"`` that mirrors the
    HeldDecision's ``detail["dimension"]`` tag onto the one field a frozen,
    ``extra="forbid"`` Decision permits.

    REQUIRE-MARKER-TO-FEED (fail-closed). A pure governance hold — an email/PDP
    Decision whose ``metadata`` has no top-level ``"dimension"`` key — returns False,
    so it can never feed the per-tenant calibration set and poison the
    SELECTION-CONDITIONAL presence conformal floor (valid only over the
    escalated/presence-held population; see this module's banner).

    HONEST EDGE (verified against live code 2026-06-22): NO production producer
    stamps ``metadata["dimension"]="presence"`` onto a ``decision_store`` Decision
    today — a presence ABSTAIN becomes only a ``HeldDecision`` in the
    ``HeldDecisionSink`` (surfaced at ``/held``), never a stored Decision with a
    ``decision_id`` the seal route can resolve. So the seal-route calibration channel
    that gates on this predicate is fail-closed INERT until a presence-hold→Decision
    persister is built. The live presence calibration fuel today is the L2
    ``/v1/presence/profile/correct`` route (``_maybe_feed_calibration``).
    """
    meta = _extract(decision, "metadata")
    if not isinstance(meta, dict):
        return False
    return meta.get("dimension") == PRESENCE_ORIGIN_DIMENSION


def _verdict_value(decision: Any) -> str | None:
    """The decision's governance verdict as a plain string (for label context),
    tolerant of an enum, a string, or absence."""
    v = _extract(decision, "verdict")
    if v is None:
        return None
    return getattr(v, "value", None) or str(v)


def _confidence_value(decision: Any) -> float | None:
    """The decision's overall confidence as a float (for label context), or None."""
    c = _extract(decision, "confidence")
    if c is None:
        return None
    try:
        return float(c)
    except (TypeError, ValueError):
        return None


class PresenceCalibrationFeed:
    """Per-tenant calibration writer. Construct once and wire it into the
    orchestrator's ``/decisions/{id}/seal`` handler; it never edits main.py."""

    def __init__(self, *, base_dir: str | Path | None = None) -> None:
        self._dir = Path(base_dir) if base_dir is not None else Path(
            os.environ.get("TEX_PRESENCE_CALIBRATION_DIR", _DEFAULT_DIR)
        )

    # ---- paths --------------------------------------------------------

    def scores_path(self, tenant: str) -> Path:
        """The file ``TEX_CONFORMAL_CALIBRATION_PATH`` should point at for this
        tenant. May not exist yet (no calibrated mode below the n-floor)."""
        return self._dir / f"{_safe_tenant(tenant)}.scores"

    def _ledger_path(self, tenant: str) -> Path:
        return self._dir / f"{_safe_tenant(tenant)}.calib.jsonl"

    def _provenance_path(self, tenant: str) -> Path:
        return self._dir / f"{_safe_tenant(tenant)}.scores.provenance.json"

    # ---- write path ---------------------------------------------------

    def record_resolution(
        self,
        *,
        tenant: str,
        decision: Any,
        human_verdict: str,
        channel: str = "unknown",
    ) -> bool:
        """Feed one sealed human resolution into this tenant's calibration set.

        Returns True iff a real calibration point was recorded. Feeds ONLY a
        ``refused`` resolution (confirmed-true decisive error → ``was_safe=False``);
        ``approved``/``held`` return False without writing. Never fabricates a
        score: if the decision carries no usable ``final_score``, returns False.
        Idempotent per ``decision_id`` (re-resolving updates, never double-counts).

        ``channel`` tags WHICH labeling path produced this point — ``"seal"`` (a
        named human resolution at ``/decisions/{id}/seal``) vs ``"explicit-correction"``
        (the L2 ``/correct`` route) vs ``"unknown"`` (an unattributed direct caller).
        The seal/correction stream is SELECTIVELY labeled, so a future propensity /
        IPW model (arXiv:2508.10149) needs to know the channel + decision context to
        de-bias the floor; we record both alongside the score. The conformal scores
        FILE is unchanged — only this audit LEDGER carries the extra fields, so the
        loader's ``calibrated``-mode contract is untouched.
        """
        hv = (human_verdict or "").strip().lower()
        # Only the confirmed-true-error label feeds (outcome_autoseal: refused →
        # was_safe=False). approved (false alarm) and held (unknown) do NOT.
        if hv != "refused":
            return False

        raw_score = _extract(decision, "final_score")
        decision_id = _extract(decision, "decision_id")
        if raw_score is None or decision_id is None:
            return False
        try:
            score = float(raw_score)
        except (TypeError, ValueError):
            return False
        if not (0.0 <= score <= 1.0):
            # final_score is a fused risk in [0,1]; anything else is not the score
            # the gate's loader expects — refuse rather than feed a bad point.
            _logger.warning(
                "calibration feed: final_score %r out of [0,1] for decision %s; "
                "not feeding",
                raw_score,
                decision_id,
            )
            return False

        entry = {
            "decision_id": str(decision_id),
            "final_score": score,
            "human_verdict": hv,
            # Provenance of the label (the labeling path) + decision context retained
            # so a later propensity/IPW correction can de-bias the SELECTIVE labeling.
            # NOTE: this is post-hoc context for MODELING propensity — NOT the
            # decision-time selection probability IPW ideally logs (the seal route is
            # post-hoc and cannot observe it); that remains a deferred refinement.
            "channel": channel,
            "decision_verdict": _verdict_value(decision),
            "decision_confidence": _confidence_value(decision),
            "recorded_at": datetime.now(UTC).isoformat(),
        }
        ledger = self._ledger_path(tenant)
        with _path_lock(ledger):
            entries = self._read_ledger(ledger)
            entries = [e for e in entries if e.get("decision_id") != str(decision_id)]
            entries.append(entry)
            self._write_ledger(ledger, entries)
            self._regenerate(tenant, entries)
        return True

    def forget_resolution(self, *, tenant: str, decision_id: str) -> bool:
        """Right-to-be-forgotten for the flywheel: drop a tenant's calibration
        contribution(s) for ``decision_id`` and regenerate the scores file. Returns
        True iff something was removed. A forgotten DERIVED contribution leaves no
        calibration residue."""
        ledger = self._ledger_path(tenant)
        with _path_lock(ledger):
            entries = self._read_ledger(ledger)
            kept = [e for e in entries if e.get("decision_id") != str(decision_id)]
            if len(kept) == len(entries):
                return False
            self._write_ledger(ledger, kept)
            self._regenerate(tenant, kept)
            return True

    # ---- status (telemetry / tests) ----------------------------------

    def label_count(self, tenant: str) -> int:
        """How many confirmed calibration labels this tenant has accrued (ledger
        rows). A cheap audit counter — the gate surfaces it on the verdict as
        ``calibration_n`` so the active mode is explainable (n vs MIN_CALIBRATION_N)
        without building the full :meth:`status` dict."""
        return len(self._read_ledger(self._ledger_path(tenant)))

    def status(self, tenant: str) -> dict[str, Any]:
        """Honest snapshot: how many points, whether calibrated mode is active,
        and the selection-conditional coverage label."""
        entries = self._read_ledger(self._ledger_path(tenant))
        n = len(entries)
        return {
            "tenant": tenant,
            "n": n,
            "min_n": MIN_CALIBRATION_N,
            "calibrated_active": n >= MIN_CALIBRATION_N,
            "scores_path": str(self.scores_path(tenant)),
            "coverage_semantics": _COVERAGE_SEMANTICS,
        }

    # ---- internals ----------------------------------------------------

    @staticmethod
    def _read_ledger(path: Path) -> list[dict[str, Any]]:
        if not path.exists():
            return []
        out: list[dict[str, Any]] = []
        try:
            for line in path.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    out.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        except OSError:
            _logger.exception("calibration feed: failed reading ledger %s", path)
        return out

    @staticmethod
    def _write_ledger(path: Path, entries: list[dict[str, Any]]) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        body = "\n".join(json.dumps(e, sort_keys=True) for e in entries)
        path.write_text(body + ("\n" if body else ""), encoding="utf-8")

    def _regenerate(self, tenant: str, entries: list[dict[str, Any]]) -> None:
        """(Re)build the scores file the conformal loader reads. Below the n-floor
        the scores file is REMOVED so the loader returns None and the gate stays
        honestly transductive — a tiny selection-biased sample never poses as a
        formal calibration."""
        scores_path = self.scores_path(tenant)
        prov_path = self._provenance_path(tenant)
        scores = [float(e["final_score"]) for e in entries if "final_score" in e]

        if len(scores) < MIN_CALIBRATION_N:
            for p in (scores_path, prov_path):
                with contextlib.suppress(FileNotFoundError):
                    p.unlink()
            return

        scores_path.parent.mkdir(parents=True, exist_ok=True)
        scores_path.write_text(
            "\n".join(repr(s) for s in scores) + "\n", encoding="utf-8"
        )
        prov_path.write_text(
            json.dumps(
                {
                    "tenant": tenant,
                    "n": len(scores),
                    "source": "human-resolved (refused) presence holds — real "
                    "Decision.final_score of confirmed-true decisive errors",
                    "coverage_semantics": _COVERAGE_SEMANTICS,
                    "min_n": MIN_CALIBRATION_N,
                    "generated_at": datetime.now(UTC).isoformat(),
                },
                indent=2,
                sort_keys=True,
            ),
            encoding="utf-8",
        )


@contextlib.contextmanager
def tenant_calibration_env(feed: PresenceCalibrationFeed, tenant: str) -> Iterator[str]:
    """Point ``TEX_CONFORMAL_CALIBRATION_PATH`` at this tenant's scores file for the
    duration of the gate call, under a process-global lock so concurrent
    multi-tenant gate calls in one worker serialize (single-flight) and cannot leak
    one tenant's calibration path into another's read. Restores the prior value on
    exit. Yields the path it set.

    Usage (orchestrator, NOT this session): ``with tenant_calibration_env(feed,
    tenant): envelope = gate.evaluate(...)``.
    """
    path = str(feed.scores_path(tenant))
    with _ENV_LOCK:
        prior = os.environ.get("TEX_CONFORMAL_CALIBRATION_PATH")
        os.environ["TEX_CONFORMAL_CALIBRATION_PATH"] = path
        try:
            yield path
        finally:
            if prior is None:
                os.environ.pop("TEX_CONFORMAL_CALIBRATION_PATH", None)
            else:
                os.environ["TEX_CONFORMAL_CALIBRATION_PATH"] = prior


@contextlib.contextmanager
def calibration_disabled_env() -> Iterator[None]:
    """Force ``transductive`` mode for the enclosed conformal computation by
    removing ``TEX_CONFORMAL_CALIBRATION_PATH`` for its duration, under the SAME
    process-global lock :func:`tenant_calibration_env` uses (so the two compose
    without a cross-thread env race). Restores the prior value on exit.

    The gate uses this to compute its transductive *baseline* before consulting a
    tenant's calibrated file — so a globally-set calibration path can never leak
    into a tenant-scoped baseline, and the monotone combine (gate side) always has
    a clean reference point.
    """
    with _ENV_LOCK:
        prior = os.environ.pop("TEX_CONFORMAL_CALIBRATION_PATH", None)
        try:
            yield
        finally:
            if prior is not None:
                os.environ["TEX_CONFORMAL_CALIBRATION_PATH"] = prior


def calibration_available(feed: PresenceCalibrationFeed, tenant: str) -> bool:
    """True iff this tenant has a calibrated scores file on disk. Because the feed
    is the SOLE producer and withholds the file below ``MIN_CALIBRATION_N`` (the
    writer-side floor; see module banner), existence ⇒ n ≥ MIN_CALIBRATION_N ⇒
    calibrated mode is legitimately engageable. Fail-safe: any error ⇒ False."""
    try:
        return feed.scores_path(tenant).exists()
    except Exception:  # noqa: BLE001 — availability is advisory; never raise into the gate
        return False


def default_calibration_feed() -> PresenceCalibrationFeed:
    """The feed the gate's reader AND the seal-flow writer share by default.

    Both default their ``base_dir`` to ``TEX_PRESENCE_CALIBRATION_DIR`` (else
    ``./data/presence_calibration``), so a tenant's scores file written by the seal
    hook is the very file the gate reads — they agree on the path by construction.
    A fresh instance each call (it holds only a ``Path``); no global mutable state,
    so tests can repoint it by setting that env var.
    """
    return PresenceCalibrationFeed()


@dataclass(frozen=True, slots=True)
class CalibrationResolution:
    """The minimal sealed-resolution the calibration hook consumes.

    The orchestrator builds this inside ``/decisions/{id}/seal`` from the
    SERVER-LOOKED-UP ``Decision`` (``decision_store.get(...)``) and the named human
    act — NEVER a request-body score, so a client cannot inject a calibration point.

      * ``decision`` — must expose ``final_score`` ∈ [0,1] and ``decision_id``.
      * ``human_verdict`` — ``"approved" | "held" | "refused"`` (only ``refused``
        produces a label; the others record nothing — see
        :meth:`PresenceCalibrationFeed.record_resolution`).
      * ``channel`` — the labeling path; defaults to ``"seal"`` because this
        dataclass IS the seal-route hook's resolution type. Other channels (e.g. the
        L2 ``/correct`` route) pass their own when they call
        :meth:`PresenceCalibrationFeed.record_resolution` directly.
    """

    decision: Any
    human_verdict: str
    channel: str = "seal"


def record_resolution_for_calibration(
    tenant: str,
    resolution: Any,
    *,
    feed: PresenceCalibrationFeed | None = None,
) -> bool:
    """ORCHESTRATOR HOOK — wire this into the ``/decisions/{id}/seal`` flow, AFTER
    a presence-tagged held decision is sealed. Feeds one sealed human resolution
    into ``tenant``'s per-tenant calibration set (each confirmed ``refused``
    resolution = one label; ``approved``/``held`` record nothing). Returns True iff
    a real calibration label was recorded.

    ``resolution`` is a :class:`CalibrationResolution` (recommended) or any object/
    dict exposing ``decision`` and ``human_verdict`` — duck-typed so the
    orchestrator need not import this module's dataclass.

    Contract + honest edges:
      * ``tenant`` MUST be the AUTHENTICATED request tenant. ``Decision`` carries no
        tenant field in this codebase, so the hook cannot derive it; passing the
        wrong tenant would mis-route the label. Per-tenant isolation is the caller's
        contract at this boundary.
      * NEVER raises into the seal flow. Capture is best-effort (mirrors
        ``outcome_autoseal``): any error is logged and returns False, so a
        calibration hiccup can never sink a seal.
    """
    feed = feed or default_calibration_feed()
    decision = _extract(resolution, "decision")
    human_verdict = _extract(resolution, "human_verdict")
    channel = _extract(resolution, "channel", "seal") or "seal"
    if decision is None or human_verdict is None:
        return False
    try:
        return feed.record_resolution(
            tenant=tenant,
            decision=decision,
            human_verdict=str(human_verdict),
            channel=str(channel),
        )
    except Exception:  # noqa: BLE001 — best-effort capture; must not break the seal
        _logger.exception(
            "calibration hook: failed recording resolution for tenant %r", tenant
        )
        return False


def forget_resolution_for_calibration(
    tenant: str,
    decision_id: str,
    *,
    feed: PresenceCalibrationFeed | None = None,
) -> bool:
    """ORCHESTRATOR HOOK — right-to-be-forgotten for the flywheel. Drop a tenant's
    calibration contribution(s) for ``decision_id`` and regenerate the scores file
    (which the writer re-withholds if the count falls back below
    ``MIN_CALIBRATION_N``). Returns True iff something was removed. Never raises."""
    feed = feed or default_calibration_feed()
    try:
        return feed.forget_resolution(tenant=tenant, decision_id=str(decision_id))
    except Exception:  # noqa: BLE001 — forgetting must degrade gracefully, never raise
        _logger.exception(
            "calibration hook: failed forgetting %s for tenant %r", decision_id, tenant
        )
        return False
