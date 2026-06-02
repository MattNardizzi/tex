"""
Declared-vs-observed intent — alignment as a sealed, deterministic grade.

Tex seals an agent's *declared* purpose at birth (from a self-declared
card, a connector description, an operator note). Monitoring later measures
the action shape the agent actually exercised against that sealed
declaration. The gap is a signal nobody else has, because nobody else
sealed the original (DISCOVERY_DOCTRINE §3.7).

The hard part is comparing the two honestly. The field's frontier is
"intent distance" — embed the declared intent and the observed actions
into a shared space and measure deviation — and the lesson it teaches is
that a *keyword* match is trivially bypassed: an agent that renames
``disableMonitoring`` to ``suppressLogs`` slips a substring matcher while
doing the identical thing. A semantic comparison catches it.

But the witness has three constraints a generic intent monitor does not:

  * **Deterministic.** The grade is sealed into an append-only log and must
    re-derive identically on replay. A live embedding model or an LLM
    judge is non-deterministic and would make the seal unreproducible.
  * **Content-free.** The comparison runs over *what an agent reached for*
    (action types, capability categories) — never over prompt or output
    text. Crossing that line turns the log into a regulated data store.
  * **Offline-verifiable.** A relying party re-checks the seal holding only
    the public key and the sealed inputs — so the scoring function cannot
    depend on a network service.

The resolution is a **capability taxonomy**: a controlled vocabulary of
behavioural categories. Both the declared-intent text and the observed
action types are classified into the *same* categories, then compared.
That is rename-resistant the way an embedding is (``suppress_logs`` and
``disable_monitoring`` both map to ``observability_tamper``), while staying
fully deterministic, content-free, and offline. The scorer is injectable —
the default is this deterministic taxonomy; an operator who accepts a model
dependency can supply an embedding scorer — and the *method* is sealed
beside the verdict (§4), so a later re-grade under a better scorer can find
every certificate that used the old one.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Mapping, Protocol, runtime_checkable

# ---------------------------------------------------------------------------
# Capability taxonomy
# ---------------------------------------------------------------------------
#
# A controlled vocabulary of behavioural categories, each with the keyword
# stems that map an action type or a phrase in a declared intent onto it.
# The categories are deliberately coarse: the goal is "is this behaviour the
# kind of thing the agent said it would do," not a fine-grained label. Stems
# are matched as word-ish substrings, so "suppress_logs", "logSuppression",
# and "suppress logging" all land on the same category. New stems are cheap
# to add; the category set is the stable contract.

CAPABILITY_TAXONOMY: dict[str, tuple[str, ...]] = {
    "communication": (
        "email", "mail", "send", "message", "notify", "notification",
        "reply", "chat", "slack", "teams", "sms", "outreach", "compose",
    ),
    "data_read": (
        "read", "query", "fetch", "lookup", "search", "retrieve", "get",
        "list", "report", "analyze", "analyse", "summarize", "summarise",
        "inspect", "view", "select",
    ),
    "data_write": (
        "write", "update", "insert", "create", "modify", "edit", "patch",
        "upsert", "record", "save", "store", "append", "post",
    ),
    "data_delete": (
        "delete", "remove", "purge", "drop", "erase", "wipe", "destroy",
        "revoke",
    ),
    "file_ops": (
        "file", "upload", "download", "document", "attachment", "blob",
        "object", "sharepoint", "drive", "s3",
    ),
    "code_execution": (
        "code", "execute", "exec", "run", "script", "shell", "command",
        "interpreter", "compile", "deploy", "build", "ci", "pipeline",
    ),
    "finance": (
        "pay", "payment", "invoice", "transfer", "transaction", "charge",
        "refund", "billing", "ledger", "wire", "settle", "reconcile",
        "purchase", "trade",
    ),
    "identity_admin": (
        "permission", "role", "grant", "consent", "privilege", "access",
        "iam", "directory", "provision", "deprovision", "credential",
        "token", "key", "rotate", "admin", "rbac", "policy",
    ),
    "observability_tamper": (
        "log", "audit", "monitor", "monitoring", "trace", "telemetry",
        "suppress", "disable", "silence", "mute", "clear", "tamper",
    ),
    "scheduling": (
        "schedule", "calendar", "meeting", "event", "reminder", "appointment",
        "book", "booking",
    ),
    "web_browse": (
        "browse", "web", "http", "url", "crawl", "scrape", "navigate",
        "website", "page",
    ),
    "tool_use": (
        "tool", "function", "mcp", "plugin", "api", "invoke", "call",
        "integration",
    ),
}

# Stems compiled once for speed; each maps to its category.
_STEM_TO_CATEGORY: dict[str, str] = {
    stem: category
    for category, stems in CAPABILITY_TAXONOMY.items()
    for stem in stems
}

_TOKEN_RE = re.compile(r"[a-z0-9]+")


def _tokens(text: str) -> list[str]:
    """Split arbitrary text / an action-type string into lowercase tokens."""
    return _TOKEN_RE.findall(text.casefold())


def _categories_for_tokens(tokens: list[str]) -> set[str]:
    """Map a bag of tokens onto the taxonomy categories they imply."""
    cats: set[str] = set()
    for tok in tokens:
        # Exact stem, then stem-as-prefix (so "scheduling" hits "schedule"
        # and "reconciliation" hits "reconcile") — bounded, deterministic.
        cat = _STEM_TO_CATEGORY.get(tok)
        if cat is not None:
            cats.add(cat)
            continue
        for stem, category in _STEM_TO_CATEGORY.items():
            if tok.startswith(stem) or stem.startswith(tok):
                if len(tok) >= 3 and abs(len(tok) - len(stem)) <= 6:
                    cats.add(category)
                    break
    return cats


def classify_intent(declared_intent: str) -> set[str]:
    """The capability categories a declared-intent string commits to."""
    return _categories_for_tokens(_tokens(declared_intent))


def classify_action_type(action_type: str) -> set[str]:
    """The capability categories an observed action type belongs to."""
    return _categories_for_tokens(_tokens(action_type))


# ---------------------------------------------------------------------------
# Pluggable scorer
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class IntentAlignment:
    """
    The graded, sealed answer to "is this agent behaving within what it
    declared?" — distribution-aware, never a bare claim.

    ``coverage`` is the share of observed behavioural *mass* (weighted by
    how often each action type fires) that falls inside a declared
    category. ``divergence`` is its complement: the mass outside the
    declaration — the part of the agent's behaviour it never said it would
    do. ``method`` records which scorer produced the grade, so the seal can
    be re-derived or re-graded later.
    """

    declared_categories: tuple[str, ...]
    observed_categories: tuple[str, ...]
    consistent_categories: tuple[str, ...]
    divergent_categories: tuple[str, ...]
    coverage: float
    divergence: float
    method: str
    note: str


@runtime_checkable
class IntentScorer(Protocol):
    """A scorer comparing a declared intent to an observed action distribution."""

    method: str

    def score(
        self, declared_intent: str, action_type_dist: Mapping[str, float]
    ) -> IntentAlignment: ...


class TaxonomyIntentScorer:
    """
    The default scorer: deterministic, content-free, offline-verifiable.

    Classifies the declared intent and each observed action type into the
    shared capability taxonomy, then weights each observed category by the
    action distribution mass behind it. Rename-resistant by construction —
    it compares categories, not strings — so the ``suppress_logs`` /
    ``disable_monitoring`` rename that defeats a substring matcher lands on
    the same ``observability_tamper`` category here.
    """

    method = "taxonomy_v1"

    def score(
        self, declared_intent: str, action_type_dist: Mapping[str, float]
    ) -> IntentAlignment:
        declared = classify_intent(declared_intent or "")

        # Weight each observed *category* by the distribution mass of the
        # action types that map to it. An action type that maps to no
        # category contributes its mass to an "uncategorized" bucket, which
        # counts as divergent (we cannot prove it was declared).
        cat_mass: dict[str, float] = {}
        total = 0.0
        uncategorized_mass = 0.0
        for action_type, weight in action_type_dist.items():
            w = float(weight)
            if w <= 0.0:
                continue
            total += w
            cats = classify_action_type(action_type)
            if not cats:
                uncategorized_mass += w
                continue
            share = w / len(cats)
            for c in cats:
                cat_mass[c] = cat_mass.get(c, 0.0) + share

        observed = set(cat_mass)
        if total <= 0.0:
            return IntentAlignment(
                declared_categories=tuple(sorted(declared)),
                observed_categories=(),
                consistent_categories=(),
                divergent_categories=(),
                coverage=0.0,
                divergence=0.0,
                method=self.method,
                note="no behaviour observed yet (cold start)",
            )

        consistent = observed & declared
        divergent = observed - declared

        inside_mass = sum(cat_mass[c] for c in consistent)
        coverage = inside_mass / total
        divergence = 1.0 - coverage

        if not declared:
            note = "nothing was declared; behaviour cannot be graded against intent"
        elif not divergent and uncategorized_mass <= 0.0:
            note = "behaviour consistent with the sealed declaration"
        else:
            note = "behaviour falls partly outside the sealed declaration"

        return IntentAlignment(
            declared_categories=tuple(sorted(declared)),
            observed_categories=tuple(sorted(observed)),
            consistent_categories=tuple(sorted(consistent)),
            divergent_categories=tuple(sorted(divergent)),
            coverage=round(coverage, 6),
            divergence=round(divergence, 6),
            method=self.method,
            note=note,
        )


# The default scorer instance the engine uses unless one is injected.
DEFAULT_INTENT_SCORER: IntentScorer = TaxonomyIntentScorer()

# Above this share of behavioural mass outside the declaration, the drift is
# consequential enough to be worth a human's attention (the held path). Kept
# conservative; tuned per estate later.
INTENT_DIVERGENCE_REVIEW_THRESHOLD: float = 0.5
