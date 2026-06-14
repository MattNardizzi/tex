"""
Action-class reversibility × blast-radius structural floor (Wave 2, leap L4).

[Architecture: Layer 4 (Execution Governance)] — feeds the structural FORBID
floor (``tex.specialists.structural_floor``), alongside Rule-of-Two
(``tex.contracts.rule_of_two``) and RV4 path policies (``tex.contracts.rv4_path``).

The principle
-------------
Some actions are *structurally* dangerous independent of how clean the content
looks: an **irreversible** action with a **public / external blast radius** —
a wire transfer, a force-push to a shared branch, a tweet from the org account,
a ``DROP TABLE`` on production — has no robust undo and an audience Tex cannot
recall. A probabilistic specialist that scores such a request 0.1 ("looks
routine") must not be able to wave it through, and a specialist that scores it
0.9 must not be what stops it either: the stop is owed to the *structure of the
action*, not to a classifier's confidence.

This contract makes that a deterministic floor over two declared axes:

  * **Reversibility** — can the effect be undone? ``REVERSIBLE`` (cleanly
    undoable) ⊑ ``RECOVERABLE`` (undoable with effort / a compensating action)
    ⊑ ``IRREVERSIBLE`` (no undo) ⊑ ``UNKNOWN`` (uncharacterised — treated as the
    most dangerous, fail-closed).
  * **BlastRadius** — who/what does the effect reach? ``SELF`` (the agent's own
    scratch) ⊑ ``TENANT`` (one org / private) ⊑ ``PUBLIC`` (external parties,
    third systems, irrevocable broadcast) ⊑ ``UNKNOWN`` (fail-closed top).

Both axes are a **join-semilattice** under the most-dangerous-wins high-water
mark (``join = max``), exactly like the FIDES capability lattice
(``tex.camel.capability``). An action is a sequence of steps; its class is the
**worst-step join** of every declared step. The deterministic cell map is::

        blast →     SELF      TENANT     PUBLIC     UNKNOWN
    rev ↓
    REVERSIBLE    NEUTRAL   NEUTRAL    ABSTAIN    ABSTAIN
    RECOVERABLE   NEUTRAL   NEUTRAL    ABSTAIN    ABSTAIN
    IRREVERSIBLE  ABSTAIN   ABSTAIN    FORBID     FORBID
    UNKNOWN       ABSTAIN   ABSTAIN    FORBID     FORBID

  * **FORBID** — irreversible-or-worse × public-or-worse: the proven worst
    corner → structural FORBID (the only cell wired into the floor this wave).
  * **ABSTAIN** — exactly one axis is in its dangerous tier: uncertain, not a
    proof → a *hold*. **Recorded only this wave**; it does not raise an operator
    hold yet (see "Scope / honest descope" below).
  * **NEUTRAL** — both axes safe: a zero-cost no-op; the action routes normally.

Why this is a structural proof, not a probability
-------------------------------------------------
The FORBID cell is a deterministic conjunction over declared structural labels.
It never reads any specialist's ``risk_score``; it can only ever *raise* a
verdict toward caution (PERMIT/ABSTAIN → FORBID), never relax one. That is what
makes it eligible for the structural FORBID floor — a surface paraphrase or a
confident probabilistic score cannot route around it. (Nasr et al., "The
Attacker Moves Second", arXiv:2510.09023, 2025, demonstrates adaptive attacks
bypassing detector-based defenses; we read that as motivation to prefer
structural proofs over probabilistic detectors — our inference, not the paper's
stated thesis.)

The bounded part — and an honest novelty claim
----------------------------------------------
A lattice floor is **not novel** on its own: the reversibility-class × blast-
radius framing mirrors the controls *proposed* for OWASP AISVS 1.01 (§9.2.6/
9.2.7, OWASP/AISVS issue #820 / PR #822) — note these are a **proposal**; the
*published* AISVS §9.2 (1.0) carries only the human-approval/irreversibility
controls 9.2.1–9.2.4, not a reversibility-class taxonomy or a blast-radius axis.
Heuristic pre-execution reversibility classifiers also already exist (GoEX,
arXiv:2404.06921, which states it gives "no guarantees"; AUP; relative
reachability) — all **bound-free**.

What is genuinely first-of-kind (and survived a deliberate refutation pass) is
the **composition**: binding the deterministic lattice floor to a finite-sample,
distribution-free upper bound on its *under-classification rate* — how often the
floor fails to FORBID an action whose ground truth is must-FORBID. The bound
itself is standard RCPS machinery (Bates, Angelopoulos, Lei, Malik & Jordan,
"Distribution-Free, Risk-Controlling Prediction Sets", JACM 2021,
arXiv:2101.02703): a one-sided Hoeffding–Bentkus UCB on a bounded i.i.d. loss.
Because the floor is a **fixed** structural map (no data-tuned cutoff), this is
the *single-hypothesis* case — a post-hoc certificate of an unchangeable rule,
**not** an RCPS λ-selection. We reuse ``crc_gate.hoeffding_bentkus_ucb`` rather
than reimplement it; no λ ever moves the runtime floor (that would make it
data-dependent and score-fireable — the very thing we forbid).

``arXiv:2603.14332`` is **deliberately not cited here**: it is a real paper, but
about cryptographic dynamic-capability binding, not reversibility / blast / a
lattice (it is misattributed for the lattice in some Tex roadmap notes). The
whole leap is ``research-early`` until a *field-labelled* corpus is measured —
until then every certificate reads ``certified=False`` (see the certificate).

Scope / honest descope (this wave)
----------------------------------
Only the **FORBID** cell is wired into ``detect_structural_floor`` (one additive
call). The structural floor is FORBID-only by contract — when it fires the PDP
short-circuits to FORBID — so the **ABSTAIN** cell cannot raise an operator hold
here. It is classified and recorded in the outcome / certificate, exactly as RV4
*recoverable* violations are recorded but routed to ``probguard`` rather than the
floor (``tex.contracts.rv4_path``). Surfacing the ABSTAIN cell as a hold is a
follow-up predictive-holds wire, out of scope for the one-call constraint.

Opt-in input shape (``request.metadata["action_class"]``)
---------------------------------------------------------
A zero-cost no-op when absent. Declare the action's steps::

    {"steps": [
        {"reversibility": "IRREVERSIBLE", "blast_radius": "PUBLIC"},
        {"reversibility": "REVERSIBLE",   "blast_radius": "SELF"}]}

Each step names both axes. A present step with a **missing or unparseable** axis
value fails closed to ``UNKNOWN`` for that axis (the caller used the feature but
could not characterise the step — uncertainty is the dangerous tier). A present
block with **no usable steps** declares no action and is a NEUTRAL no-op — an
empty declaration never fabricates a FORBID. The contract reads ONLY this block;
it never inspects ``request.recipient`` / ``channel`` / ``action_type`` (that
would fire on benign default envelopes and break the opt-in no-op contract).
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from enum import IntEnum
from functools import reduce
from typing import Any, Mapping, Sequence

from pydantic import BaseModel, ConfigDict, Field

# REUSE the tested RCPS bound rather than reimplement it. crc_gate imports only
# math/dataclasses/typing/pydantic/tex.domain.verdict, so this is cycle-free.
from tex.engine.crc_gate import hoeffding_bentkus_ucb


_METADATA_KEY = "action_class"
ACTION_CLASS_CODE = "action_class.irreversible_public"
ACTION_CLASS_SPECIALIST = "action_class"


# ── The two axes (join-semilattices, UNKNOWN = fail-closed top) ─────────────


class Reversibility(IntEnum):
    """Reversibility axis. ``join = max`` — least-undoable step wins.

    ``REVERSIBLE < RECOVERABLE < IRREVERSIBLE < UNKNOWN``. ``UNKNOWN`` is a
    NEW top member (a deliberate departure from
    ``camel.capability.CapabilityLevel``, which has no UNKNOWN tier): an
    uncharacterised action is treated as *at least as dangerous as
    irreversible* (fail-closed), while staying distinguishable from a
    declared-IRREVERSIBLE action in audit evidence.
    """

    REVERSIBLE = 0
    RECOVERABLE = 1
    IRREVERSIBLE = 2
    UNKNOWN = 3

    def join(self, other: "Reversibility") -> "Reversibility":
        return Reversibility(max(int(self), int(other)))

    @property
    def is_irreversible(self) -> bool:
        """True at ``IRREVERSIBLE`` or ``UNKNOWN`` — the no-robust-undo tier."""
        return self >= Reversibility.IRREVERSIBLE


class BlastRadius(IntEnum):
    """Blast-radius axis. ``join = max`` — widest-reach step wins.

    ``SELF < TENANT < PUBLIC < UNKNOWN``. ``UNKNOWN`` is the fail-closed top
    (an uncharacterised reach is treated as public-or-worse).
    """

    SELF = 0
    TENANT = 1
    PUBLIC = 2
    UNKNOWN = 3

    def join(self, other: "BlastRadius") -> "BlastRadius":
        return BlastRadius(max(int(self), int(other)))

    @property
    def is_public(self) -> bool:
        """True at ``PUBLIC`` or ``UNKNOWN`` — the external / irrevocable tier."""
        return self >= BlastRadius.PUBLIC


class ActionClass(IntEnum):
    """Verdict class of a (reversibility, blast) cell. Monotone = more conservative.

    ``NEUTRAL < ABSTAIN < FORBID``. Higher is strictly more cautious, so the
    cell map can only ever raise caution.
    """

    NEUTRAL = 0
    ABSTAIN = 1
    FORBID = 2


# ── Strict, fail-closed coercion ────────────────────────────────────────────


def _coerce_rev(value: Any) -> Reversibility:
    """Map a declared reversibility string to a member; unparseable → UNKNOWN.

    Deliberately strict and fail-closed (the dual of ``rule_of_two._as_bool``,
    which fails *open* to "not proven"): here an absent / unrecognised value is
    uncertainty, and uncertainty is the dangerous tier, so it resolves UP to
    ``UNKNOWN`` — never silently down to ``REVERSIBLE``.
    """
    if isinstance(value, Reversibility):
        return value
    if isinstance(value, str):
        name = value.strip().upper()
        if name in Reversibility.__members__:
            return Reversibility[name]
    return Reversibility.UNKNOWN


def _coerce_blast(value: Any) -> BlastRadius:
    """Map a declared blast-radius string to a member; unparseable → UNKNOWN."""
    if isinstance(value, BlastRadius):
        return value
    if isinstance(value, str):
        name = value.strip().upper()
        if name in BlastRadius.__members__:
            return BlastRadius[name]
    return BlastRadius.UNKNOWN


# ── The fixed cell map (no data, no λ — pure structure) ──────────────────────


def classify_action_class(rev: Reversibility, blast: BlastRadius) -> ActionClass:
    """Deterministic (reversibility, blast) → verdict cell. FIXED — no calibration.

    FORBID iff irreversible-or-worse AND public-or-worse (the worst corner,
    UNKNOWN swept in by ``is_irreversible`` / ``is_public``); ABSTAIN iff exactly
    one axis is in its dangerous tier; NEUTRAL otherwise. This function never
    reads a score, a certificate, or any datum outside its two arguments.
    """
    if rev.is_irreversible and blast.is_public:
        return ActionClass.FORBID
    if rev.is_irreversible or blast.is_public:
        return ActionClass.ABSTAIN
    return ActionClass.NEUTRAL


def _join_steps(
    steps: Sequence[Any],
) -> tuple[Reversibility, BlastRadius, int]:
    """Worst-step join over declared steps → (worst_rev, worst_blast, n_valid).

    Only Mapping entries are valid steps; each contributes its coerced
    (reversibility, blast), with a missing axis failing closed to ``UNKNOWN``.
    Non-Mapping entries are skipped. ``n_valid == 0`` (no usable steps) signals
    "nothing declared" — the caller resolves that to a NEUTRAL no-op rather
    than fabricating a FORBID from an empty declaration.
    """
    rev = Reversibility.REVERSIBLE  # ⊥ identity for max-join
    blast = BlastRadius.SELF
    n_valid = 0
    for entry in steps:
        if not isinstance(entry, Mapping):
            continue
        n_valid += 1
        rev = rev.join(_coerce_rev(entry.get("reversibility")))
        blast = blast.join(_coerce_blast(entry.get("blast_radius")))
    return rev, blast, n_valid


# ── Outcome (mirrors RuleOfTwoOutcome) ───────────────────────────────────────


@dataclass(frozen=True, slots=True)
class ActionClassOutcome:
    """Result of classifying one request's declared action class."""

    fired: bool  # True iff the FORBID cell — the only cell wired to the floor
    action_class: ActionClass
    worst_reversibility: Reversibility
    worst_blast: BlastRadius
    n_steps: int
    reason: str
    code: str
    evidence: dict[str, Any] = field(default_factory=dict)

    @property
    def is_hold(self) -> bool:
        """ABSTAIN cell — recorded only this wave (not an operator hold yet)."""
        return self.action_class is ActionClass.ABSTAIN


NEUTRAL_ACTION_CLASS = ActionClassOutcome(
    fired=False,
    action_class=ActionClass.NEUTRAL,
    worst_reversibility=Reversibility.REVERSIBLE,
    worst_blast=BlastRadius.SELF,
    n_steps=0,
    reason="",
    code=ACTION_CLASS_CODE,
    evidence={},
)


def classify_action_class_block(raw: Mapping[str, Any]) -> ActionClassOutcome:
    """Pure classifier over an ``action_class`` metadata block."""
    steps = raw.get("steps")
    if not isinstance(steps, Sequence) or isinstance(steps, (str, bytes)):
        return NEUTRAL_ACTION_CLASS

    worst_rev, worst_blast, n_valid = _join_steps(steps)
    if n_valid == 0:
        # A present-but-empty declaration is no action to classify → no-op.
        return NEUTRAL_ACTION_CLASS

    cell = classify_action_class(worst_rev, worst_blast)
    fired = cell is ActionClass.FORBID

    evidence: dict[str, Any] = {
        "worst_reversibility": worst_rev.name,
        "worst_blast": worst_blast.name,
        "n_steps": n_valid,
        "cell": cell.name,
    }

    if fired:
        reason = (
            f"L4 ActionClass lattice: worst-step join is "
            f"{worst_rev.name} reversibility × {worst_blast.name} blast radius "
            f"over {n_valid} declared step(s) — an irreversible, public-blast "
            "action with no proof of containment or undo. Structural FORBID."
        )
    elif cell is ActionClass.ABSTAIN:
        reason = (
            f"L4 ActionClass lattice: worst-step join is "
            f"{worst_rev.name} × {worst_blast.name} — one axis in its dangerous "
            "tier. Held for review (recorded; not yet surfaced this wave)."
        )
    else:
        reason = ""

    return ActionClassOutcome(
        fired=fired,
        action_class=cell,
        worst_reversibility=worst_rev,
        worst_blast=worst_blast,
        n_steps=n_valid,
        reason=reason,
        code=ACTION_CLASS_CODE,
        evidence=evidence,
    )


def evaluate_action_class(request: Any) -> ActionClassOutcome:
    """Evaluate the action-class contract against a PDP request.

    Returns ``NEUTRAL_ACTION_CLASS`` (a zero-cost no-op) when the request carries
    no ``action_class`` metadata block. Reads ONLY that block — never the request
    envelope (recipient / channel / action_type).
    """
    metadata = getattr(request, "metadata", None)
    if not isinstance(metadata, Mapping):
        return NEUTRAL_ACTION_CLASS
    raw = metadata.get(_METADATA_KEY)
    if not isinstance(raw, Mapping):
        return NEUTRAL_ACTION_CLASS
    return classify_action_class_block(raw)


# ── Cell-map version (so a stale certificate is detectable) ──────────────────


def _compute_cell_map_version() -> str:
    """Stable short hash of the FIXED cell table. Changes iff the map changes."""
    rows = [
        f"{rev.name}x{blast.name}={classify_action_class(rev, blast).name}"
        for rev in Reversibility
        for blast in BlastRadius
    ]
    canonical = ";".join(rows)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:12]


CELL_MAP_VERSION = _compute_cell_map_version()


# ── Under-classification certificate (audit-only; never read at runtime) ─────


class ActionClassCertificate(BaseModel):
    """Auditable bound on how often the FIXED lattice floor under-classifies.

    The runtime floor NEVER reads this object — it is offline evidence about the
    floor's error rate on a labelled corpus, mirroring ``crc_gate.CRCCertificate``.
    The headline number is ``certified_under_classification_rate``: a finite-
    sample, distribution-free (Hoeffding–Bentkus) upper bound on the *under-
    classification* rate — the fraction of must-FORBID actions the floor fails to
    FORBID (because their declared features under-state the truth).

    Honesty gate: ``certified`` is True ONLY for a ``field``-measured corpus whose
    bound clears ``alpha``. A ``synthetic`` corpus computes the bound honestly but
    stays ``certified=False`` — its mis-declaration rate is a model we wrote, not a
    measured field rate (the ``nanozk`` lesson: the name must not over-promise).
    With no corpus the certificate is inert (``enabled=False``), exactly like the
    CRC gate without calibration.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    enabled: bool = Field(description="Whether any labelled corpus backed this certificate.")
    certified: bool = Field(
        description=(
            "Whether the under-classification rate carries a finite-sample field "
            "guarantee. True only for a 'field' corpus whose UCB <= alpha; "
            "'synthetic' and 'none' always read False (research-early)."
        )
    )
    corpus_kind: str = Field(
        default="none", description="'none' | 'synthetic' | 'field'."
    )
    alpha: float = Field(
        ge=0.0, le=1.0, description="Target upper bound on the under-classification rate."
    )
    delta: float = Field(
        ge=0.0, le=1.0, description="Failure probability of the bound (confidence = 1 - delta)."
    )
    bound_method: str = Field(default="hoeffding_bentkus")
    cell_map_version: str = Field(
        description="Hash of the FIXED cell table the cert was computed against."
    )

    # ── under-classification (marginal: missed-FORBID over the whole corpus) ──
    n_calibration: int = Field(ge=0, description="Calibration corpus size.")
    n_must_forbid: int = Field(
        ge=0, description="Count of ground-truth must-FORBID cases (conditional denominator)."
    )
    empirical_under_classification_rate: float = Field(
        ge=0.0, le=1.0, description="missed-FORBID / n_calibration on the corpus."
    )
    under_risk_upper_bound: float = Field(
        ge=0.0,
        le=1.0,
        description="Hoeffding-Bentkus UCB on the true under-classification rate at 1 - delta.",
    )
    certified_under_classification_rate: float = Field(
        ge=0.0,
        le=1.0,
        description=(
            "The number Tex stands behind: the certified upper bound on the "
            "under-classification rate. Equals under_risk_upper_bound when "
            "certified, else 1.0."
        ),
    )

    # ── conditional false-negative rate (audit: missed-FORBID / must-FORBID) ──
    empirical_false_negative_rate: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
        description="Audit: missed-FORBID / n_must_forbid (the adversary-facing recall miss).",
    )
    false_negative_upper_bound: float = Field(
        default=1.0,
        ge=0.0,
        le=1.0,
        description="Audit: Hoeffding-Bentkus UCB on the conditional false-negative rate.",
    )

    # ── held-out validation (the 200-test split) ─────────────────────────────
    n_test: int = Field(default=0, ge=0, description="Held-out test split size.")
    empirical_holdout_under_rate: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
        description="Under-classification rate measured on the held-out test split.",
    )
    holdout_within_bound: bool = Field(
        default=False,
        description=(
            "Whether the held-out under-classification rate fell within the "
            "calibration UCB — an out-of-sample sanity check that the bound "
            "transfers (not itself a guarantee)."
        ),
    )

    # ── over-classification (audit only; never gates runtime) ────────────────
    empirical_over_classification_rate: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
        description="Audit: false-FORBID (safe action forbidden) / n_calibration.",
    )
    over_risk_upper_bound: float = Field(
        default=1.0,
        ge=0.0,
        le=1.0,
        description="Audit: Hoeffding-Bentkus UCB on the over-classification rate.",
    )


@dataclass(frozen=True, slots=True)
class ActionClassCase:
    """One labelled corpus point.

    ``declared_steps`` is what the agent *declares* (the only thing the lattice
    reads); ``ground_truth_must_forbid`` is the hidden truth. The two can DISAGREE
    — that disagreement is precisely the under-classification the certificate
    bounds, and is what keeps the bound non-circular.
    """

    declared_steps: tuple[tuple[str, str], ...]  # ((reversibility, blast_radius), ...)
    ground_truth_must_forbid: bool

    def predicted(self) -> ActionClass:
        step_dicts = [
            {"reversibility": r, "blast_radius": b} for r, b in self.declared_steps
        ]
        rev, blast, _ = _join_steps(step_dicts)
        return classify_action_class(rev, blast)

    @property
    def is_under_classification(self) -> bool:
        """Must-FORBID by ground truth, but the floor does NOT forbid it."""
        return self.ground_truth_must_forbid and self.predicted() is not ActionClass.FORBID

    @property
    def is_over_classification(self) -> bool:
        """Safe by ground truth, but the floor forbids it (false block)."""
        return (not self.ground_truth_must_forbid) and self.predicted() is ActionClass.FORBID


def _inert_certificate(*, alpha: float, delta: float) -> ActionClassCertificate:
    return ActionClassCertificate(
        enabled=False,
        certified=False,
        corpus_kind="none",
        alpha=alpha,
        delta=delta,
        cell_map_version=CELL_MAP_VERSION,
        n_calibration=0,
        n_must_forbid=0,
        empirical_under_classification_rate=0.0,
        under_risk_upper_bound=1.0,
        certified_under_classification_rate=1.0,
    )


def certify_action_class(
    calibration: Sequence[ActionClassCase],
    *,
    holdout: Sequence[ActionClassCase] = (),
    alpha: float = 0.05,
    delta: float = 0.05,
    corpus_kind: str = "synthetic",
) -> ActionClassCertificate:
    """Bound the FIXED lattice floor's under-classification rate on a labelled corpus.

    Single-hypothesis (the floor is fixed, not selected from the data), so the
    one-sided Hoeffding–Bentkus UCB needs no multiplicity correction. With an
    empty corpus the certificate is inert (``certified=False``, UCB 1.0). With a
    ``synthetic`` corpus the bound is computed but ``certified`` stays False (the
    rate is a model, not a field measurement). ``certified`` flips True only for a
    ``field`` corpus whose UCB clears ``alpha``.
    """
    n = len(calibration)
    if n == 0:
        return _inert_certificate(alpha=alpha, delta=delta)

    misses = sum(1 for c in calibration if c.is_under_classification)
    overs = sum(1 for c in calibration if c.is_over_classification)
    n_must_forbid = sum(1 for c in calibration if c.ground_truth_must_forbid)

    r_under = misses / n
    ucb_under = hoeffding_bentkus_ucb(r_under, n, delta)

    r_fn = (misses / n_must_forbid) if n_must_forbid else 0.0
    ucb_fn = hoeffding_bentkus_ucb(r_fn, n_must_forbid, delta)

    r_over = overs / n
    ucb_over = hoeffding_bentkus_ucb(r_over, n, delta)

    n_test = len(holdout)
    if n_test:
        holdout_misses = sum(1 for c in holdout if c.is_under_classification)
        r_holdout = holdout_misses / n_test
    else:
        r_holdout = 0.0
    holdout_within = bool(n_test) and (r_holdout <= ucb_under + 1e-12)

    # Honesty gate: only a FIELD corpus can certify; synthetic computes-but-abstains.
    certified = (corpus_kind == "field") and (ucb_under <= alpha)
    certified_rate = ucb_under if certified else 1.0

    return ActionClassCertificate(
        enabled=True,
        certified=certified,
        corpus_kind=corpus_kind,
        alpha=alpha,
        delta=delta,
        cell_map_version=CELL_MAP_VERSION,
        n_calibration=n,
        n_must_forbid=n_must_forbid,
        empirical_under_classification_rate=round(r_under, 6),
        under_risk_upper_bound=round(min(1.0, max(0.0, ucb_under)), 6),
        certified_under_classification_rate=round(min(1.0, max(0.0, certified_rate)), 6),
        empirical_false_negative_rate=round(r_fn, 6),
        false_negative_upper_bound=round(min(1.0, max(0.0, ucb_fn)), 6),
        n_test=n_test,
        empirical_holdout_under_rate=round(r_holdout, 6),
        holdout_within_bound=holdout_within,
        empirical_over_classification_rate=round(r_over, 6),
        over_risk_upper_bound=round(min(1.0, max(0.0, ucb_over)), 6),
    )


# The shipped default: inert, certified=False, corpus_kind='none' — until a real
# FIELD-labelled corpus exists, exactly the CRC gate's inert posture.
ACTION_CLASS_CERT = certify_action_class([])


# ── Synthetic labelled corpus (research fixture; seeded; anti-circular) ──────

# Truth marginals: skewed so must-FORBID (IRREVERSIBLE × PUBLIC) is ~33% — enough
# must-FORBID mass that the mis-declaration channel yields a robust count of
# genuine under-classification events. Shared by every corpus builder below so
# there is exactly ONE truth model (a second one could silently drift).
_TRUTH_REV_LEVELS = (
    Reversibility.REVERSIBLE,
    Reversibility.RECOVERABLE,
    Reversibility.IRREVERSIBLE,
)
_TRUTH_REV_WEIGHTS = (0.25, 0.20, 0.55)
_TRUTH_BLAST_LEVELS = (BlastRadius.SELF, BlastRadius.TENANT, BlastRadius.PUBLIC)
_TRUTH_BLAST_WEIGHTS = (0.20, 0.20, 0.60)


def _sample_action_class_case(rng, *, p_under: float, p_over: float) -> ActionClassCase:
    """Draw ONE anti-circular labelled case (the shared per-case sampler).

    The label ``ground_truth_must_forbid`` is decided from a LATENT
    ``(rev_true, blast_true)`` sampled independently of what gets declared; the
    declared features the lattice actually reads are then produced by a SEPARATE
    mis-declaration channel that under-states a fraction ``p_under`` of must-FORBID
    cases and over-states a fraction ``p_over`` of benign ones. Because declared ≠
    true on a non-trivial slice, the under-classification rate is a GENUINE
    non-zero quantity — not the trivial 0 you would get if ground truth were
    derived from the declared bits (the nanozk-class lie this guards against).

    The exact draw order — choices(rev), choices(blast), the mis-declaration
    branch, randint(steps), randrange(slot) — is load-bearing: every corpus
    builder shares it so a given seed yields the identical stream.
    """
    rev_true = rng.choices(_TRUTH_REV_LEVELS, weights=_TRUTH_REV_WEIGHTS, k=1)[0]
    blast_true = rng.choices(_TRUTH_BLAST_LEVELS, weights=_TRUTH_BLAST_WEIGHTS, k=1)[0]
    must_forbid = (
        rev_true is Reversibility.IRREVERSIBLE and blast_true is BlastRadius.PUBLIC
    )

    decl_rev, decl_blast = rev_true, blast_true
    if must_forbid and rng.random() < p_under:
        # Under-state ONE axis so the floor misses a truly-must-FORBID action.
        if rng.random() < 0.5:
            decl_rev = Reversibility.RECOVERABLE
        else:
            decl_blast = BlastRadius.TENANT
    elif (not must_forbid) and rng.random() < p_over:
        # Over-state a benign action into the FORBID corner (false block).
        decl_rev, decl_blast = Reversibility.IRREVERSIBLE, BlastRadius.PUBLIC

    # Embed the dangerous declared step among 1..5 benign steps so the
    # worst-step join is genuinely exercised.
    n_steps = rng.randint(1, 5)
    steps: list[tuple[str, str]] = [
        (Reversibility.REVERSIBLE.name, BlastRadius.SELF.name)
        for _ in range(n_steps)
    ]
    steps[rng.randrange(n_steps)] = (decl_rev.name, decl_blast.name)

    return ActionClassCase(
        declared_steps=tuple(steps),
        ground_truth_must_forbid=must_forbid,
    )


def build_action_class_corpus(
    seed: int = 1729,
    n_total: int = 500,
    p_under: float = 0.50,
    p_over: float = 0.12,
) -> tuple[list[ActionClassCase], list[ActionClassCase]]:
    """Build a seeded 300-cal / 200-test labelled corpus — RESEARCH FIXTURE only.

    Anti-circularity is structural (see ``_sample_action_class_case``): declared ≠
    true on a non-trivial slice, so the under-classification rate is a GENUINE
    non-zero quantity, not the circular 0 that would fabricate a certified
    ~0.0198 bound. The default ``p_under=0.50`` deliberately injects a HIGH miss
    rate — its purpose is a non-vacuous synthetic fixture, NOT a certifiable one
    (its UCB sits far above alpha, so the certificate stays uncertified). For the
    low-rate regime where the UCB can actually clear alpha, see
    ``build_certifiable_action_class_corpus``.

    The mis-declaration rate is SYNTHETIC, so a certificate over this corpus must
    read ``corpus_kind='synthetic'`` / ``certified=False`` — it bounds the floor's
    miss rate UNDER this declaration-noise model, never a field rate. Determinism
    is via ``random.Random(seed)`` at build time only (no runtime randomness).
    """
    import random  # local: never imported into the runtime classify path

    rng = random.Random(seed)
    cases = [
        _sample_action_class_case(rng, p_under=p_under, p_over=p_over)
        for _ in range(n_total)
    ]

    calibration = cases[:300]
    test = cases[300:500]

    # Anti-circularity tripwire: the held-out split MUST contain a non-trivial
    # count of genuine under-classification events, else the bound is vacuous and
    # the synthetic model failed to inject real declaration noise.
    test_misses = sum(1 for c in test if c.is_under_classification)
    if test_misses < 20:
        raise AssertionError(
            f"corpus is near-circular: only {test_misses} under-classification "
            "events in the test split (need >= 20 for a non-vacuous bound)"
        )

    return calibration, test


def build_certifiable_action_class_corpus(
    seed: int = 20260618,
    *,
    n_calibration: int = 500,
    n_holdout: int = 2000,
    p_under: float = 0.055,
    p_over: float = 0.10,
    min_holdout_misses: int = 20,
) -> tuple[list[ActionClassCase], list[ActionClassCase]]:
    """A labelled corpus tuned to the CERTIFIABLE regime — RESEARCH FIXTURE only.

    The L4 certificate has two gates that pull in OPPOSITE directions, and a
    corpus certifies only when BOTH clear:

      * the bound gate — ``hoeffding_bentkus_ucb(under_rate, n_calibration) <=
        alpha`` — wants a LOW under-classification rate;
      * the anti-vacuity tripwire — ``>= min_holdout_misses`` genuine under-
        classification events in the holdout — wants ENOUGH absolute misses that
        the bound is not measuring an empty set.

    A single i.i.d. corpus reconciles them only at SCALE: a low mis-declaration
    rate (``p_under=0.055`` → marginal under-rate ~0.018, well under alpha=0.05)
    PLUS a large holdout (``n_holdout=2000`` → ~36 expected genuine misses, well
    over 20). At the default split the calibration UCB clears alpha with margin
    while the tripwire is satisfied several times over — which is exactly why a
    real L4 field corpus must be LARGE (see NOTES.md for the size derivation).

    Shares ``_sample_action_class_case`` verbatim with
    ``build_action_class_corpus`` — same anti-circular truth model, only the rate
    and the split sizes differ. Like every builder here the data is SYNTHETIC: it
    certifies nothing until attested + sealed as a field corpus (and a real field
    corpus is collected, not built). The ``corpus_kind='field'`` label is earned
    only through the provenance gate, never from this function.
    """
    import random  # local: never imported into the runtime classify path

    if n_calibration <= 0 or n_holdout <= 0:
        raise ValueError("n_calibration and n_holdout must be positive")

    rng = random.Random(seed)
    cases = [
        _sample_action_class_case(rng, p_under=p_under, p_over=p_over)
        for _ in range(n_calibration + n_holdout)
    ]
    calibration = cases[:n_calibration]
    holdout = cases[n_calibration:]

    # Same anti-circularity tripwire the certifier enforces: a holdout with too
    # few genuine misses yields a vacuous bound. Fail loudly at build time so a
    # mis-tuned fixture never reaches the certifier looking certifiable.
    holdout_misses = sum(1 for c in holdout if c.is_under_classification)
    if holdout_misses < min_holdout_misses:
        raise AssertionError(
            f"certifiable corpus is near-vacuous: only {holdout_misses} "
            f"under-classification events in the holdout (need >= "
            f"{min_holdout_misses}); raise n_holdout or p_under"
        )

    return calibration, holdout


__all__ = [
    "Reversibility",
    "BlastRadius",
    "ActionClass",
    "ActionClassOutcome",
    "NEUTRAL_ACTION_CLASS",
    "ACTION_CLASS_CODE",
    "ACTION_CLASS_SPECIALIST",
    "CELL_MAP_VERSION",
    "classify_action_class",
    "classify_action_class_block",
    "evaluate_action_class",
    "ActionClassCertificate",
    "ActionClassCase",
    "certify_action_class",
    "ACTION_CLASS_CERT",
    "build_action_class_corpus",
    "build_certifiable_action_class_corpus",
]
