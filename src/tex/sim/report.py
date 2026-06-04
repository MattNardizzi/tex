"""
report.py — the ten-second read.

Collects Checks into pass/fail/skip tallies, a verdict-mix breakdown, and the
list of failures (the where-it-breaks output). Prints a compact console
summary and emits machine-readable JSON the cockpit can render.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from typing import Any

from tex.sim.oracle import Check, FAIL, PASS, SKIP


@dataclass
class Report:
    scenario: str
    org: str
    tenant_id: str
    seed: int
    estate_summary: dict[str, Any]
    checks: list[Check] = field(default_factory=list)
    verdict_counts: dict[str, int] = field(default_factory=dict)
    started_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    finished_at: str | None = None

    def add(self, check: Check | list[Check]) -> None:
        if isinstance(check, list):
            self.checks.extend(check)
        else:
            self.checks.append(check)

    def tally(self) -> dict[str, int]:
        t = {PASS: 0, FAIL: 0, SKIP: 0}
        for c in self.checks:
            t[c.status] = t.get(c.status, 0) + 1
        return t

    @property
    def ok(self) -> bool:
        return self.tally()[FAIL] == 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "scenario": self.scenario,
            "org": self.org,
            "tenant_id": self.tenant_id,
            "seed": self.seed,
            "estate": self.estate_summary,
            "tally": self.tally(),
            "verdict_counts": self.verdict_counts,
            "ok": self.ok,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "failures": [asdict(c) for c in self.checks if c.status == FAIL],
            "checks": [asdict(c) for c in self.checks],
        }

    def write_json(self, path: str) -> None:
        with open(path, "w") as f:
            json.dump(self.to_dict(), f, indent=2)

    def console(self) -> str:
        t = self.tally()
        lines = []
        lines.append("=" * 64)
        lines.append(f"  TEX SANDBOX — {self.scenario.upper()}   ({self.org})")
        lines.append("=" * 64)
        es = self.estate_summary
        lines.append(f"  estate     : {es.get('total')} agents "
                     f"({es.get('idp_visible')} IdP, {es.get('shadow')} shadow)  seed={self.seed}")
        if self.verdict_counts:
            vc = self.verdict_counts
            lines.append(f"  verdicts   : PERMIT {vc.get('PERMIT',0)}  "
                         f"ABSTAIN {vc.get('ABSTAIN',0)}  FORBID {vc.get('FORBID',0)}  "
                         f"other {sum(v for k,v in vc.items() if k not in ('PERMIT','ABSTAIN','FORBID'))}")
        lines.append(f"  checks     : {t[PASS]} PASS   {t[FAIL]} FAIL   {t[SKIP]} SKIP")
        lines.append("-" * 64)
        if t[FAIL]:
            lines.append("  WHERE IT BROKE:")
            for c in self.checks:
                if c.status == FAIL:
                    lines.append(f"    ✗ {c.name}: {c.detail}")
        else:
            lines.append("  no failures — every assertion held.")
        lines.append("=" * 64)
        verdict = "GREEN ✓" if self.ok else "RED ✗"
        lines.append(f"  RESULT: {verdict}")
        lines.append("=" * 64)
        return "\n".join(lines)
