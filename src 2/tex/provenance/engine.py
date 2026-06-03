"""
Behavioural provenance engine — the identity-by-behaviour primitive.

The engine consumes the gate's decision stream (an agent's action-ledger
entries), derives a behavioural signature, resolves it against the
identities it already knows, and seals the outcome into the transparency
log. It is the component that lets Tex stop trusting what an agent says
about itself and start proving who it is by what it does.

Resolution outcomes:

  * No confident match               → BIRTH. A new actor is witnessed; a
                                        behavioural birth certificate is
                                        sealed, anchored to attested
                                        identity, not claimed metadata.
  * Confident match, same agent_id    → SIGHTING. Identity confirmed,
                                        baseline refreshed.
  * Confident match, *different*      → REIDENTIFIED. The same actor under
    agent_id (a rotation/rename)        a new name or key — the case
                                        directory identity cannot follow.
                                        Sealed, and surfaced for a human
                                        when consequential.
  * Same agent_id, behaviour diverged → DRIFT. The known agent stopped
                                        behaving like itself. Above
                                        threshold, surfaced for a human.

Every outcome carries a graded confidence, sealed alongside the fact.
The engine never asserts identity; it states a belief and the evidence.

Cold-start honesty: a signature below the warm threshold yields a low-
confidence resolution regardless of similarity, and the engine says so.
Behaviour alone, without a shared stable anchor, is capped — strong
evidence, not proof. These caps are the witness refusing to overclaim.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Iterable, Sequence
from uuid import UUID

from tex.domain.agent import ActionLedgerEntry
from tex.domain.signal_trust import SignalTrustTier
from tex.provenance.distance import behavioral_confidence
from tex.provenance.intent import (
    DEFAULT_INTENT_SCORER,
    INTENT_DIVERGENCE_REVIEW_THRESHOLD,
    IntentScorer,
)
from tex.provenance.ledger import BehavioralProvenanceLedger
from tex.provenance.models import (
    BehavioralBirthCertificate,
    CoverageBoundary,
    ProvenanceEventKind,
    ProvenanceMatch,
    ProvenanceResolution,
)
from tex.provenance.signature import (
    WARM_OBSERVATION_THRESHOLD,
    BehavioralSignature,
)

# Confidence at or above which two signatures are treated as the same
# actor for an automatic SIGHTING/REIDENTIFIED seal.
REIDENTIFY_THRESHOLD: float = 0.86

# When a cross-identity match lands in this band, it is strong enough to
# seal as a candidate but ambiguous enough that a *merge* (collapsing two
# identities into one) must be a human's call — surfaced as a held
# decision. Below the lower bound it is not a match; at/above
# REIDENTIFY_THRESHOLD with no ambiguity it can seal directly.
MERGE_REVIEW_LOWER: float = 0.72

# Drift: how far a known agent's fresh signature may diverge from its
# sealed baseline before the engine flags it. Expressed as 1 - confidence
# of self-similarity, so a higher number is more drift.
DRIFT_THRESHOLD: float = 0.40


@dataclass
class _KnownIdentity:
    agent_id: UUID
    signature: BehavioralSignature
    signal_tier: SignalTrustTier
    born_at: datetime
    born_at_sequence: int
    birth_record_hash: str
    last_seen_at: datetime
    total_observations: int = 0
    # The purpose the agent declared at birth (self-declared card,
    # connector description). Sealed once; compared against observed
    # behaviour later. None when nothing was declared.
    declared_intent: str | None = None
    # Every admissibility tier that has confirmed this agent — the union
    # that the coverage boundary is graded from. Starts with the birth
    # tier and grows as other planes sight the same actor.
    confirmed_tiers: set[SignalTrustTier] = field(default_factory=set)


@dataclass
class BehavioralProvenanceEngine:
    """
    Stateful resolver over behavioural identities, backed by the sealed
    ledger. Thread-safe. The engine holds the current signature per known
    agent; the ledger holds the immutable, signed history.
    """

    ledger: BehavioralProvenanceLedger
    _known: dict[str, _KnownIdentity] = field(default_factory=dict)
    _lock: threading.RLock = field(default_factory=threading.RLock)
    # The declared-vs-observed intent comparator. Default is the
    # deterministic, content-free, offline-verifiable taxonomy scorer; an
    # operator may inject an embedding scorer. The method is sealed beside
    # any grade so it can be re-derived or re-graded later.
    intent_scorer: IntentScorer = field(default=DEFAULT_INTENT_SCORER)

    # ------------------------------------------------------------------
    def observe(
        self,
        *,
        agent_id: UUID,
        entries: Sequence[ActionLedgerEntry] | Iterable[ActionLedgerEntry],
        signal_tier: SignalTrustTier = SignalTrustTier.NETWORK_OBSERVED,
    ) -> ProvenanceResolution:
        """
        Observe an actor's behaviour window, resolve its identity, seal
        the outcome, and return the graded resolution.

        ``signal_tier`` is the admissibility grade of the vantage these
        observations came from — the enforcement gate is NETWORK_OBSERVED
        (tamper-resistant); a self-declared feed would be SELF_DECLARED.
        """
        signature = BehavioralSignature.from_actions(entries)
        if signature.observation_count == 0:
            return ProvenanceResolution(
                observed_signature_hash=signature.signature_hash,
                event_kind=ProvenanceEventKind.SIGHTING,
                confidence=0.0,
                warm=False,
                note="no observations",
            )

        with self._lock:
            known_self = self._known.get(str(agent_id))

            # --- Case 1: we already know this agent_id ---
            if known_self is not None:
                self_conf = behavioral_confidence(known_self.signature, signature)
                drift = 1.0 - self_conf
                if signature.is_warm and known_self.signature.is_warm and drift >= DRIFT_THRESHOLD:
                    return self._seal_drift(known_self, signature, signal_tier, drift)
                return self._seal_sighting(known_self, signature, signal_tier, self_conf)

            # --- Case 2: unknown agent_id — is it a known actor renamed? ---
            best, alternatives = self._best_cross_match(agent_id, signature)
            if best is not None and best.confidence >= REIDENTIFY_THRESHOLD:
                return self._seal_reidentified(
                    agent_id, signature, signal_tier, best, alternatives
                )
            if best is not None and best.confidence >= MERGE_REVIEW_LOWER:
                # Strong-but-ambiguous: seal as a new identity AND flag the
                # possible merge for a human. The held-decision path.
                resolution = self._seal_birth(
                    agent_id, signature, signal_tier, ambiguous_match=best, alternatives=alternatives
                )
                return resolution

            # --- Case 3: genuinely new actor ---
            return self._seal_birth(agent_id, signature, signal_tier)

    # ------------------------------------------------------------------ matching
    def _best_cross_match(
        self, agent_id: UUID, signature: BehavioralSignature
    ) -> tuple[ProvenanceMatch | None, tuple[ProvenanceMatch, ...]]:
        matches: list[ProvenanceMatch] = []
        for key, known in self._known.items():
            if key == str(agent_id):
                continue
            conf = behavioral_confidence(known.signature, signature)
            if conf <= 0.0:
                continue
            from tex.provenance.distance import _shared_anchors

            matches.append(
                ProvenanceMatch(
                    agent_id=known.agent_id,
                    confidence=conf,
                    signature_hash=known.signature.signature_hash,
                    shared_anchors=_shared_anchors(known.signature, signature),
                )
            )
        matches.sort(key=lambda m: m.confidence, reverse=True)
        best = matches[0] if matches else None
        return best, tuple(matches[1:4])

    # ------------------------------------------------------------------ sealers
    def _seal_birth(
        self,
        agent_id: UUID,
        signature: BehavioralSignature,
        signal_tier: SignalTrustTier,
        ambiguous_match: ProvenanceMatch | None = None,
        alternatives: tuple[ProvenanceMatch, ...] = (),
    ) -> ProvenanceResolution:
        detail = {"signature": signature.to_jsonable()}
        if ambiguous_match is not None:
            detail["possible_merge_with"] = str(ambiguous_match.agent_id)
            detail["possible_merge_confidence"] = round(ambiguous_match.confidence, 6)
        record = self.ledger.append(
            event_kind=ProvenanceEventKind.BIRTH,
            agent_id=agent_id,
            signature_hash=signature.signature_hash,
            confidence=1.0,
            signal_tier=int(signal_tier),
            observation_count=signature.observation_count,
            detail=detail,
        )
        now = datetime.now(UTC)
        self._known[str(agent_id)] = _KnownIdentity(
            agent_id=agent_id,
            signature=signature,
            signal_tier=signal_tier,
            born_at=now,
            born_at_sequence=record.sequence,
            birth_record_hash=record.record_hash,
            last_seen_at=now,
            total_observations=signature.observation_count,
            confirmed_tiers={signal_tier},
        )
        return ProvenanceResolution(
            observed_signature_hash=signature.signature_hash,
            event_kind=ProvenanceEventKind.BIRTH,
            best_match=ambiguous_match,
            alternatives=alternatives,
            confidence=1.0,
            warm=signature.is_warm,
            requires_human=ambiguous_match is not None,
            note=(
                f"possible merge with {ambiguous_match.agent_id} "
                f"at {ambiguous_match.confidence:.2f} — needs a human"
                if ambiguous_match is not None
                else "new actor witnessed; birth sealed"
            ),
        )

    def _seal_sighting(
        self,
        known: _KnownIdentity,
        signature: BehavioralSignature,
        signal_tier: SignalTrustTier,
        confidence: float,
    ) -> ProvenanceResolution:
        self.ledger.append(
            event_kind=ProvenanceEventKind.SIGHTING,
            agent_id=known.agent_id,
            signature_hash=signature.signature_hash,
            confidence=confidence,
            signal_tier=int(max(signal_tier, known.signal_tier)),
            observation_count=signature.observation_count,
            detail={"signature": signature.to_jsonable()},
        )
        known.signature = signature
        known.signal_tier = max(signal_tier, known.signal_tier)
        known.confirmed_tiers.add(signal_tier)
        known.last_seen_at = datetime.now(UTC)
        known.total_observations += signature.observation_count
        return ProvenanceResolution(
            observed_signature_hash=signature.signature_hash,
            event_kind=ProvenanceEventKind.SIGHTING,
            best_match=ProvenanceMatch(
                agent_id=known.agent_id,
                confidence=confidence,
                signature_hash=signature.signature_hash,
                shared_anchors=0,
            ),
            confidence=confidence,
            warm=signature.is_warm,
            note="identity confirmed",
        )

    def _seal_reidentified(
        self,
        agent_id: UUID,
        signature: BehavioralSignature,
        signal_tier: SignalTrustTier,
        best: ProvenanceMatch,
        alternatives: tuple[ProvenanceMatch, ...],
    ) -> ProvenanceResolution:
        self.ledger.append(
            event_kind=ProvenanceEventKind.REIDENTIFIED,
            agent_id=agent_id,
            signature_hash=signature.signature_hash,
            confidence=best.confidence,
            signal_tier=int(signal_tier),
            observation_count=signature.observation_count,
            linked_agent_id=best.agent_id,
            detail={
                "recognized_as": str(best.agent_id),
                "shared_anchors": best.shared_anchors,
                "signature": signature.to_jsonable(),
            },
        )
        now = datetime.now(UTC)
        # Register the new alias as its own known identity, linked by the
        # sealed record to the prior one. A merge (collapsing them) stays a
        # human decision; the engine only witnesses the link.
        self._known[str(agent_id)] = _KnownIdentity(
            agent_id=agent_id,
            signature=signature,
            signal_tier=signal_tier,
            born_at=now,
            born_at_sequence=self.ledger.list_for_agent(agent_id)[0].sequence,
            birth_record_hash=self.ledger.list_for_agent(agent_id)[0].record_hash,
            last_seen_at=now,
            total_observations=signature.observation_count,
        )
        return ProvenanceResolution(
            observed_signature_hash=signature.signature_hash,
            event_kind=ProvenanceEventKind.REIDENTIFIED,
            best_match=best,
            alternatives=alternatives,
            confidence=best.confidence,
            warm=signature.is_warm,
            requires_human=best.confidence < REIDENTIFY_THRESHOLD + 0.1,
            note=f"recognized as prior actor {best.agent_id} at {best.confidence:.2f}",
        )

    def _seal_drift(
        self,
        known: _KnownIdentity,
        signature: BehavioralSignature,
        signal_tier: SignalTrustTier,
        drift: float,
    ) -> ProvenanceResolution:
        self.ledger.append(
            event_kind=ProvenanceEventKind.DRIFT,
            agent_id=known.agent_id,
            signature_hash=signature.signature_hash,
            confidence=1.0 - drift,
            signal_tier=int(signal_tier),
            observation_count=signature.observation_count,
            detail={"drift": round(drift, 6), "baseline": known.signature.signature_hash, "signature": signature.to_jsonable()},
        )
        known.signature = signature
        known.last_seen_at = datetime.now(UTC)
        return ProvenanceResolution(
            observed_signature_hash=signature.signature_hash,
            event_kind=ProvenanceEventKind.DRIFT,
            best_match=ProvenanceMatch(
                agent_id=known.agent_id,
                confidence=1.0 - drift,
                signature_hash=signature.signature_hash,
                shared_anchors=0,
            ),
            confidence=1.0 - drift,
            warm=signature.is_warm,
            requires_human=True,
            note=f"behaviour diverged from baseline (drift {drift:.2f})",
        )

    # ------------------------------------------------------------------ reads
    def reidentify(
        self, signature: BehavioralSignature, *, top_k: int = 5
    ) -> tuple[ProvenanceMatch, ...]:
        """Graded matches of a candidate signature against known identities."""
        with self._lock:
            from tex.provenance.distance import _shared_anchors

            matches = [
                ProvenanceMatch(
                    agent_id=k.agent_id,
                    confidence=behavioral_confidence(k.signature, signature),
                    signature_hash=k.signature.signature_hash,
                    shared_anchors=_shared_anchors(k.signature, signature),
                )
                for k in self._known.values()
            ]
        matches = [m for m in matches if m.confidence > 0.0]
        matches.sort(key=lambda m: m.confidence, reverse=True)
        return tuple(matches[:top_k])

    def birth_certificate(self, agent_id: UUID) -> BehavioralBirthCertificate | None:
        with self._lock:
            known = self._known.get(str(agent_id))
        if known is None:
            return None
        birth = self.ledger.birth_record(agent_id)
        if birth is None:
            return None
        sig = known.signature
        return BehavioralBirthCertificate(
            agent_id=agent_id,
            signature_hash=sig.signature_hash,
            signal_tier=int(known.signal_tier),
            signal_tier_label=known.signal_tier.label,
            system_prompt_hash=sig.system_prompt_hash,
            tool_manifest_hash=sig.tool_manifest_hash,
            memory_hash=sig.memory_hash,
            born_at=known.born_at,
            born_at_sequence=known.born_at_sequence,
            last_seen_at=known.last_seen_at,
            observation_count=known.total_observations,
            declared_intent=known.declared_intent,
            birth_record_hash=known.birth_record_hash,
            signing_key_id=self.ledger.signing_key_id,
        )

    # ------------------------------------------------------------------ discovery birth

    def register_birth(
        self,
        *,
        agent_id: UUID,
        signal_tier: SignalTrustTier,
        system_prompt_hash: str | None = None,
        tool_manifest_hash: str | None = None,
        memory_hash: str | None = None,
        declared_intent: str | None = None,
        detail: dict | None = None,
    ) -> ProvenanceResolution:
        """
        Seal a behavioural BIRTH for an agent discovered through the
        reconciliation path, anchored to its *attested* identity at the
        moment of discovery — not to claimed metadata.

        This is what makes discovery and provenance one flow: the instant
        reconciliation promotes a candidate to a real agent, its birth is
        sealed into the same transparency log that the gate's continuous
        feed will later confirm by behaviour. The cert is cold (no actions
        observed yet) but it carries the discovery signal's admissibility
        tier and whatever stable anchors the platform exposed, so a later
        SIGHTING from the gate confirms the *same* identity rather than
        minting a second one.

        Idempotent: a second call for an already-known agent widens the
        coverage union but never seals a second birth for one identity.

        Silent by construction. Sealing a birth is never a reason to break
        the voice — a new thing being discovered is exactly the event §1
        forbids Tex from speaking about.
        """
        with self._lock:
            existing = self._known.get(str(agent_id))
            if existing is not None:
                existing.confirmed_tiers.add(signal_tier)
                existing.signal_tier = max(existing.signal_tier, signal_tier)
                return ProvenanceResolution(
                    observed_signature_hash=existing.signature.signature_hash,
                    event_kind=ProvenanceEventKind.SIGHTING,
                    confidence=1.0,
                    warm=existing.signature.is_warm,
                    note="already witnessed; coverage widened, no second birth",
                )

            sig = BehavioralSignature(
                observation_count=0,
                system_prompt_hash=system_prompt_hash,
                tool_manifest_hash=tool_manifest_hash,
                memory_hash=memory_hash,
            )._with_hash()

            seal_detail = {"discovery_birth": True, "signal_tier": signal_tier.label}
            # Seal the stable anchors so a restart can reconstruct this cold
            # identity's signature exactly (event-sourcing replay), not just
            # its hash. Content-free: these are hashes, never text.
            if system_prompt_hash:
                seal_detail["system_prompt_hash"] = system_prompt_hash
            if tool_manifest_hash:
                seal_detail["tool_manifest_hash"] = tool_manifest_hash
            if memory_hash:
                seal_detail["memory_hash"] = memory_hash
            if declared_intent:
                seal_detail["declared_intent"] = declared_intent
            if detail:
                seal_detail.update(detail)

            record = self.ledger.append(
                event_kind=ProvenanceEventKind.BIRTH,
                agent_id=agent_id,
                signature_hash=sig.signature_hash,
                confidence=1.0,
                signal_tier=int(signal_tier),
                observation_count=0,
                detail=seal_detail,
            )
            now = datetime.now(UTC)
            self._known[str(agent_id)] = _KnownIdentity(
                agent_id=agent_id,
                signature=sig,
                signal_tier=signal_tier,
                born_at=now,
                born_at_sequence=record.sequence,
                birth_record_hash=record.record_hash,
                last_seen_at=now,
                total_observations=0,
                declared_intent=declared_intent,
                confirmed_tiers={signal_tier},
            )
            return ProvenanceResolution(
                observed_signature_hash=sig.signature_hash,
                event_kind=ProvenanceEventKind.BIRTH,
                confidence=1.0,
                warm=False,
                note=f"discovery birth sealed at {signal_tier.label}",
            )

    # ------------------------------------------------------------------ dormancy seals

    def _signature_hash_for(self, agent_id: UUID) -> str:
        known = self._known.get(str(agent_id))
        if known is not None:
            return known.signature.signature_hash
        # An agent Tex never behaviourally witnessed (discovered but silent)
        # still gets a stable, content-free anchor for its lifecycle seals.
        import hashlib

        return hashlib.sha256(f"agent:{agent_id}".encode("ascii")).hexdigest()

    def seal_sleep(
        self,
        agent_id: UUID,
        *,
        signal_tier: SignalTrustTier = SignalTrustTier.NETWORK_OBSERVED,
        detail: dict | None = None,
    ):
        """
        Seal that Tex put an idle agent to sleep on its own authority.
        Silent and autonomous — the seal is the record, not a notification.
        The behavioural signature is frozen (not altered) by sleep.
        """
        with self._lock:
            return self.ledger.append(
                event_kind=ProvenanceEventKind.SLEPT,
                agent_id=agent_id,
                signature_hash=self._signature_hash_for(agent_id),
                confidence=1.0,
                signal_tier=int(signal_tier),
                detail=detail or {},
            )

    def seal_wake(
        self,
        agent_id: UUID,
        *,
        signal_tier: SignalTrustTier = SignalTrustTier.NETWORK_OBSERVED,
        detail: dict | None = None,
    ):
        """Seal a deliberate, human-initiated wake of a sleeping agent."""
        with self._lock:
            rec = self.ledger.append(
                event_kind=ProvenanceEventKind.WOKE,
                agent_id=agent_id,
                signature_hash=self._signature_hash_for(agent_id),
                confidence=1.0,
                signal_tier=int(signal_tier),
                detail=detail or {},
            )
            known = self._known.get(str(agent_id))
            if known is not None:
                known.last_seen_at = datetime.now(UTC)
            return rec

    def last_event(self, agent_id: UUID, kind: ProvenanceEventKind):
        """Most-recent sealed record of a given kind for an agent, or None."""
        records = self.ledger.list_for_agent(agent_id)
        for rec in reversed(records):
            if rec.event_kind is kind:
                return rec
        return None

    # ------------------------------------------------------------------ coverage

    def coverage_boundary(self, agent_id: UUID) -> CoverageBoundary | None:
        """
        The sealed edge of sight for one agent — admissibility as a grade,
        with the honest statement of what Tex cannot see. Never a claim of
        total coverage.
        """
        with self._lock:
            known = self._known.get(str(agent_id))
            if known is None:
                return None
            tier = known.signal_tier
            tiers = sorted(known.confirmed_tiers or {tier}, reverse=True)
            warm = known.signature.is_warm
            obs = known.total_observations

        if tier >= SignalTrustTier.AUDIT_LOG:
            edge = (
                "Confirmed by a signal the workload cannot forge; "
                "admissible without qualification."
            )
        elif tier is SignalTrustTier.NETWORK_OBSERVED:
            edge = (
                "Observed at a chokepoint the workload cannot bypass while "
                "acting; a kernel or audit plane would grade it higher."
            )
        elif tier is SignalTrustTier.CONTROL_PLANE:
            edge = (
                "Known through a platform that mediates the signal; "
                "authoritative for what the platform sees, not yet observed "
                "acting at a tamper-resistant chokepoint."
            )
        else:
            edge = (
                "Known only by self-declaration — forgeable by definition; "
                "recorded as claimed, awaiting an out-of-process sighting."
            )
        if not warm and obs == 0:
            edge += " No behaviour observed yet (cold start)."

        return CoverageBoundary(
            agent_id=agent_id,
            signal_tier=int(tier),
            signal_tier_label=tier.label,
            admissibility=tier.admissibility,
            confirmed_tiers=tuple(t.label for t in tiers),
            tamper_resistant=tier.is_tamper_resistant,
            edge_of_sight=edge,
            observation_count=obs,
            warm=warm,
        )

    def intent_drift(self, agent_id: UUID) -> dict | None:
        """
        Compare an agent's *declared* intent (sealed at birth) against the
        action shape it has actually exercised, via the injected scorer.
        The gap is the signal nobody else has, because nobody else sealed
        the declaration.

        Rename-resistant by construction: the scorer compares behavioural
        *categories*, not action-type strings, so an agent that renames a
        capability to dodge a keyword filter still lands in the same
        category. ``requires_human`` is set when the divergence — the share
        of behavioural mass outside the declaration — crosses the review
        threshold, routing the consequential case to the held path.

        Returns None when nothing was declared.
        """
        with self._lock:
            known = self._known.get(str(agent_id))
            if known is None or not known.declared_intent:
                return None
            declared_intent = known.declared_intent
            action_dist = dict(known.signature.action_type_dist)
            warm = known.signature.is_warm

        alignment = self.intent_scorer.score(declared_intent, action_dist)
        requires_human = (
            warm and alignment.divergence >= INTENT_DIVERGENCE_REVIEW_THRESHOLD
        )
        return {
            "declared_intent": declared_intent,
            "declared_categories": list(alignment.declared_categories),
            "observed_categories": list(alignment.observed_categories),
            "consistent_with_declaration": list(alignment.consistent_categories),
            "outside_declaration": list(alignment.divergent_categories),
            "declaration_coverage": alignment.coverage,
            "intent_divergence": alignment.divergence,
            "scoring_method": alignment.method,
            "warm": warm,
            "requires_human": requires_human,
            "note": alignment.note,
        }

    def known_count(self) -> int:
        with self._lock:
            return len(self._known)

    # ------------------------------------------------------------------ memory
    #
    # The engine's ``_known`` map is a *projection* (a read model) over the
    # sealed ledger, which is the event store. On its own the projection is
    # process-local: a restart leaves it empty while the ledger still holds
    # the full history, so the first post-restart sighting of a known agent
    # would mint a second birth and the "continuous witness" claim would be
    # a lie. The standard event-sourcing answer is to rebuild the projection
    # by replaying the log. That is what ``rebuild_from_ledger`` does.
    #
    # Snapshots are a performance optimization, not a correctness one — the
    # discipline ("KISS until replay is slow") is to ship the interface and
    # leave it dormant: ``snapshot()`` captures the projection at a sequence,
    # and ``rebuild_from_ledger(snapshot=...)`` resumes from there instead of
    # genesis. Default replay is from genesis, which is correct at any size.

    def rebuild_from_ledger(self, *, snapshot: dict | None = None) -> int:
        """
        Reconstruct the identity projection by replaying the sealed ledger.
        Idempotent and safe to call on a fresh engine at boot. Returns the
        number of distinct identities rebuilt.

        With ``snapshot`` provided, only records after the snapshot's
        ``last_sequence`` are replayed and the snapshot's identities seed
        the projection — the resume path. Without it, the whole log is
        replayed, which is always correct.
        """
        with self._lock:
            self._known = {}
            start_after = -1
            if snapshot is not None:
                start_after = int(snapshot.get("last_sequence", -1))
                for entry in snapshot.get("identities", ()):  # seed from snapshot
                    ident = self._identity_from_snapshot(entry)
                    self._known[str(ident.agent_id)] = ident

            for record in self.ledger.list_all():
                if record.sequence <= start_after:
                    continue
                self._apply_record(record)
            return len(self._known)

    def _apply_record(self, record) -> None:
        """Fold one sealed record into the in-memory projection."""
        key = str(record.agent_id)
        kind = record.event_kind
        detail = record.detail or {}
        tier = SignalTrustTier(int(record.signal_tier))
        recorded_at = record.recorded_at

        if kind is ProvenanceEventKind.BIRTH:
            signature = self._signature_from_detail(detail)
            self._known[key] = _KnownIdentity(
                agent_id=record.agent_id,
                signature=signature,
                signal_tier=tier,
                born_at=recorded_at,
                born_at_sequence=record.sequence,
                birth_record_hash=record.record_hash,
                last_seen_at=recorded_at,
                total_observations=int(record.observation_count),
                declared_intent=detail.get("declared_intent"),
                confirmed_tiers={tier},
            )
            return

        if kind is ProvenanceEventKind.REIDENTIFIED:
            # The new alias becomes its own known identity, linked by the
            # sealed record to the prior one (a merge stays a human's call).
            signature = self._signature_from_detail(detail)
            self._known[key] = _KnownIdentity(
                agent_id=record.agent_id,
                signature=signature,
                signal_tier=tier,
                born_at=recorded_at,
                born_at_sequence=record.sequence,
                birth_record_hash=record.record_hash,
                last_seen_at=recorded_at,
                total_observations=int(record.observation_count),
                confirmed_tiers={tier},
            )
            return

        known = self._known.get(key)
        if known is None:
            # A sighting/drift/sleep for an agent whose birth we never saw
            # (e.g. a truncated log). Skip rather than fabricate a birth.
            return

        if kind in (ProvenanceEventKind.SIGHTING, ProvenanceEventKind.DRIFT):
            if "signature" in detail:
                known.signature = self._signature_from_detail(detail)
            known.signal_tier = max(known.signal_tier, tier)
            known.confirmed_tiers.add(tier)
            known.last_seen_at = recorded_at
            known.total_observations += int(record.observation_count)
        elif kind in (ProvenanceEventKind.SLEPT, ProvenanceEventKind.WOKE):
            known.last_seen_at = recorded_at

    @staticmethod
    def _signature_from_detail(detail: dict) -> BehavioralSignature:
        """Reconstruct a behavioural signature from a sealed record's detail."""
        if "signature" in detail:
            return BehavioralSignature.from_jsonable(detail["signature"])
        # A discovery (cold) birth seals only its stable anchors. Rebuild an
        # observation-free signature from them so a later behavioural
        # sighting confirms the same identity rather than minting a new one.
        return BehavioralSignature(
            observation_count=0,
            system_prompt_hash=detail.get("system_prompt_hash"),
            tool_manifest_hash=detail.get("tool_manifest_hash"),
            memory_hash=detail.get("memory_hash"),
        )._with_hash()

    def _identity_from_snapshot(self, entry: dict) -> _KnownIdentity:
        tier = SignalTrustTier(int(entry["signal_tier"]))
        return _KnownIdentity(
            agent_id=UUID(entry["agent_id"]),
            signature=BehavioralSignature.from_jsonable(entry["signature"]),
            signal_tier=tier,
            born_at=datetime.fromisoformat(entry["born_at"]),
            born_at_sequence=int(entry["born_at_sequence"]),
            birth_record_hash=entry["birth_record_hash"],
            last_seen_at=datetime.fromisoformat(entry["last_seen_at"]),
            total_observations=int(entry.get("total_observations", 0)),
            declared_intent=entry.get("declared_intent"),
            confirmed_tiers={
                SignalTrustTier(int(t)) for t in entry.get("confirmed_tiers", (int(tier),))
            },
        )

    def snapshot(self) -> dict:
        """
        Capture the projection as a resume point. Dormant by default — the
        boot path replays from genesis — but ready for the day replay time
        on a hot estate justifies it. Pairs with
        ``rebuild_from_ledger(snapshot=...)``.
        """
        with self._lock:
            last_sequence = len(self.ledger) - 1
            identities = [
                {
                    "agent_id": str(k.agent_id),
                    "signature": k.signature.to_jsonable(),
                    "signal_tier": int(k.signal_tier),
                    "born_at": k.born_at.isoformat(),
                    "born_at_sequence": k.born_at_sequence,
                    "birth_record_hash": k.birth_record_hash,
                    "last_seen_at": k.last_seen_at.isoformat(),
                    "total_observations": k.total_observations,
                    "declared_intent": k.declared_intent,
                    "confirmed_tiers": [int(t) for t in k.confirmed_tiers],
                }
                for k in self._known.values()
            ]
        return {"last_sequence": last_sequence, "identities": identities}
