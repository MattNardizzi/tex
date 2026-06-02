"""
Ignition registry — "Run discovery" said once, and only once.

Ignition is not a scan command and not a per-source connect ceremony. It
is the single moment a witness starts watching, and it surfaces exactly
one line: the count, and that Tex is beginning. After that the glass goes
clean and the inventory is pull-only — Tex does the work in the dark.

This registry is the server-side flag that makes "exactly one line" true.
It mirrors the manifesto door: ignition fires once per tenant and never
re-declares. A second ignition call after the first does not re-speak; the
door has already opened. The flag is what stops the surface from drifting
into a feed that re-announces itself.

In-memory by default — like the manifesto flag, it is intentionally
per-process state, not a durable record. The sealed inventory lives in the
ledgers; this is only the "have we said hello yet" bit.
"""

from __future__ import annotations

import threading
from datetime import UTC, datetime


_ONES = (
    "zero", "one", "two", "three", "four", "five", "six", "seven", "eight",
    "nine", "ten", "eleven", "twelve", "thirteen", "fourteen", "fifteen",
    "sixteen", "seventeen", "eighteen", "nineteen",
)
_TENS = (
    "", "", "twenty", "thirty", "forty", "fifty", "sixty", "seventy",
    "eighty", "ninety",
)


def humanize_count(n: int) -> str:
    """
    Spell a count the way Tex speaks it: "forty-one", not "41". Tex speaks
    meaning; bare digits are objects, not speech. Handles 0–9999, which
    covers any plausible estate; beyond that it falls back to digits.
    """
    if n < 0 or n > 9999:
        return str(n)
    if n < 20:
        return _ONES[n]
    if n < 100:
        tens, ones = divmod(n, 10)
        return _TENS[tens] + (f"-{_ONES[ones]}" if ones else "")
    if n < 1000:
        hundreds, rest = divmod(n, 100)
        head = f"{_ONES[hundreds]} hundred"
        return head if rest == 0 else f"{head} {humanize_count(rest)}"
    thousands, rest = divmod(n, 1000)
    head = f"{humanize_count(thousands)} thousand"
    return head if rest == 0 else f"{head} {humanize_count(rest)}"


class IgnitionRegistry:
    """Thread-safe per-tenant 'has ignition fired?' flag."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._fired_at: dict[str, datetime] = {}

    def has_fired(self, tenant: str) -> bool:
        with self._lock:
            return tenant in self._fired_at

    def fire(self, tenant: str) -> datetime:
        """Mark ignition fired for a tenant; idempotent (keeps first time)."""
        with self._lock:
            if tenant not in self._fired_at:
                self._fired_at[tenant] = datetime.now(UTC)
            return self._fired_at[tenant]

    def fired_at(self, tenant: str) -> datetime | None:
        with self._lock:
            return self._fired_at.get(tenant)

    def reset(self, tenant: str) -> None:
        """Clear the flag (operator re-ignition, tests)."""
        with self._lock:
            self._fired_at.pop(tenant, None)
