"""
Conduit seal engine — seal the grant, seal the inventory, catch the drift.

This composes the project's **verified** seal primitives — the gix transparency
log checkpoint (``interchange/gix.py``, C2SP tlog-checkpoint + Ed25519
signed-note) and the RFC 3161 external anchor whose CMS signature is actually
verified against a pinned TSA cert (``interchange/external_anchor.py``). It does
NOT use ``c2pa/timestamp.py`` (that one builds/parses RFC 3161 but never
verifies the TSA signature — the exact failure this project exists to avoid).

Conduit keeps its **own** append-only provenance chain, separate from the
governance decision ledger. That separation is deliberate and load-bearing:
the L3 count-conservation invariants are keyed on the DECISION fact kind, so a
conduit event (a sealed grant, a drift, an inventory snapshot) is — like the
deliberately-separate ``VERDICT_TRANSCRIPT`` kind — structurally invisible to
those counters. Conduit never appends to the decision ledger; it composes the
same checkpoint/anchor machinery over its own leaf sequence.

A ``ConduitReceipt`` is self-describing and verifiable **offline** by a third
party who does not trust Tex (see ``scripts/verify_conduit_receipt.py``):
recompute the leaf hash from the payload, verify Merkle inclusion against the
checkpoint root, verify the Ed25519 note signature against a pinned log key, and
— when anchored — verify the RFC 3161 token against a pinned TSA cert.
"""

from __future__ import annotations

import base64
import hashlib
import json
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from tex.discovery.conduit.grant import DirectoryGrant, canonical_scopes
from tex.discovery.connectors.base import BaseConnector, ConnectorContext, ConnectorError
from tex.domain.discovery import CandidateAgent

# RFC 9162 empty-tree root: SHA-256 of the empty string.
_EMPTY_TREE_ROOT = hashlib.sha256(b"").hexdigest()
from tex.interchange.external_anchor import (
    CheckpointAnchorRecord,
    Poster,
    anchor_subject_digest,
    submit_anchor,
    verify_anchor_receipt,
)
from tex.interchange.gix import (
    Checkpoint,
    CheckpointPublisher,
    Ed25519NoteSigner,
    Ed25519NoteVerifier,
    SignedCheckpoint,
    merkle_root,
    split_signed_note,
    verify_inclusion,
    verify_note,
)


class ConduitEventKind(StrEnum):
    """
    The provenance events conduit seals on its own chain.

    These are sealed on the conduit provenance chain, NOT the governance
    decision ledger, so the ATTEMPT/DECISION conservation counters never see
    them (the VERDICT_TRANSCRIPT discipline, achieved by chain-separation).
    """

    GRANT_SEALED = "grant_sealed"
    CONNECTION_DRIFT = "connection_drift"
    INVENTORY_SNAPSHOT_SEALED = "inventory_snapshot_sealed"


# An anchor function turns a signed checkpoint snapshot into an external
# timestamp receipt (or None to skip anchoring). Injected so this module never
# imports a network library; tests inject a local-TSA-backed function.
AnchorFn = Callable[[SignedCheckpoint], "CheckpointAnchorRecord | None"]


def canonical_json(obj: Any) -> bytes:
    """Deterministic JSON encoding used for every conduit leaf hash."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def record_hash_of(payload: dict[str, Any]) -> str:
    """The chain leaf for a payload: SHA-256 of its canonical JSON, hex."""
    return hashlib.sha256(canonical_json(payload)).hexdigest()


# --------------------------------------------------------------------------- receipt
@dataclass(frozen=True, slots=True)
class ConduitVerification:
    """What an offline verifier concluded about one receipt — fail-closed."""

    ok: bool
    failures: tuple[str, ...]
    pinned: bool
    anchor_status: str  # absent | present_unverified | verified | failed
    gen_time: datetime | None
    record_hash_hex: str

    def summary(self) -> str:
        if self.ok:
            anchor = (
                f"; external age <= {self.gen_time.isoformat()} (TSA-verified)"
                if self.anchor_status == "verified" and self.gen_time
                else f"; anchor={self.anchor_status}"
            )
            pin = "pinned key" if self.pinned else "embedded key (provide a pin to verify authorship)"
            return f"VALID against {pin}{anchor}"
        return f"INVALID: {', '.join(self.failures)}"


class ConduitReceipt(BaseModel):
    """
    A self-contained, offline-verifiable receipt for one sealed conduit event.

    Everything a third party needs to check the seal without trusting Tex: the
    sealed payload, the leaf hash, the Merkle inclusion proof, the signed
    checkpoint note, the (self-asserted) log public key — pin it out-of-band —
    and, when present, the external RFC 3161 anchor record.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    receipt_version: str = "tex-conduit-receipt/1"
    kind: ConduitEventKind
    payload: dict[str, Any]

    record_hash_hex: str = Field(min_length=64, max_length=64)
    leaf_index: int = Field(ge=0)
    tree_size: int = Field(ge=1)
    inclusion_proof_hex: tuple[str, ...] = Field(default_factory=tuple)

    checkpoint_origin: str
    checkpoint_root_hex: str = Field(min_length=64, max_length=64)
    signed_note: str
    log_key_name: str
    log_public_key_b64: str

    anchor: CheckpointAnchorRecord | None = None
    sealed_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    def verify(
        self,
        *,
        pinned_log_public_key_b64: str | None = None,
        pinned_tsa_cert_der: bytes | None = None,
    ) -> ConduitVerification:
        """Verify this receipt offline. Pass a pinned log key to verify
        authorship (don't-trust-Tex); pass a pinned TSA cert to verify age."""
        failures: list[str] = []

        # 1. Payload integrity: the leaf must be the hash of the payload.
        recomputed = record_hash_of(self.payload)
        if recomputed != self.record_hash_hex:
            failures.append("payload_hash_mismatch")

        # 2. Merkle inclusion against the checkpoint root.
        if not verify_inclusion(
            self.record_hash_hex,
            self.leaf_index,
            self.tree_size,
            self.inclusion_proof_hex,
            self.checkpoint_root_hex,
        ):
            failures.append("inclusion_failed")

        # 3. The signed note must (a) parse, (b) commit to the same root/size we
        #    proved inclusion against, and (c) verify under the log key.
        key_b64 = pinned_log_public_key_b64 or self.log_public_key_b64
        pinned = pinned_log_public_key_b64 is not None
        try:
            text, _ = split_signed_note(self.signed_note)
            cp = Checkpoint.parse(text)
            if cp.root_hash_hex != self.checkpoint_root_hex:
                failures.append("note_root_mismatch")
            if cp.tree_size != self.tree_size:
                failures.append("note_size_mismatch")
        except Exception:  # noqa: BLE001 — any malformation is fail-closed
            failures.append("note_parse_failed")
        try:
            verifier = Ed25519NoteVerifier(
                name=self.log_key_name,
                public_key_raw=base64.b64decode(key_b64.encode("ascii")),
            )
            if self.log_key_name not in verify_note(self.signed_note, [verifier]):
                failures.append("note_signature_failed")
        except Exception:  # noqa: BLE001
            failures.append("note_signature_failed")

        # 4. External anchor (optional).
        anchor_status = "absent"
        gen_time: datetime | None = None
        if self.anchor is not None:
            if self.anchor.root_hash_hex != self.checkpoint_root_hex:
                failures.append("anchor_root_mismatch")
            if pinned_tsa_cert_der is None:
                anchor_status = "present_unverified"
            else:
                av = verify_anchor_receipt(self.anchor, pinned_tsa_cert_der=pinned_tsa_cert_der)
                if av.ok:
                    anchor_status = "verified"
                    gen_time = av.gen_time
                else:
                    anchor_status = "failed"
                    failures.append(f"anchor_{av.failure_code}")

        return ConduitVerification(
            ok=not failures,
            failures=tuple(failures),
            pinned=pinned,
            anchor_status=anchor_status,
            gen_time=gen_time,
            record_hash_hex=self.record_hash_hex,
        )


# --------------------------------------------------------------------------- chain
class ConduitProvenanceChain:
    """
    Append-only sequence of conduit event leaves, sealed by a gix
    ``CheckpointPublisher``. Separate from the governance decision ledger by
    construction (see module docstring).
    """

    def __init__(
        self,
        *,
        origin: str = "tex.conduit/provenance",
        signer: Ed25519NoteSigner | None = None,
    ) -> None:
        self._leaves: list[str] = []
        self._publisher = CheckpointPublisher(
            origin=origin,
            read_record_hashes=lambda: tuple(self._leaves),
            signer=signer,
        )

    @property
    def origin(self) -> str:
        return self._publisher.origin

    @property
    def log_verifier(self) -> Ed25519NoteVerifier:
        return self._publisher.log_verifier

    def public_key_b64(self) -> str:
        return base64.b64encode(self.log_verifier.public_key_raw).decode("ascii")

    def pin(self) -> dict[str, str]:
        """The out-of-band pin a relying party verifies receipts against."""
        return {
            "log_key_name": self._publisher.origin,
            "log_public_key_b64": self.public_key_b64(),
        }

    def seal(
        self,
        kind: ConduitEventKind,
        payload: dict[str, Any],
        *,
        anchor: AnchorFn | None = None,
    ) -> ConduitReceipt:
        record_hash = record_hash_of(payload)
        leaf_index = len(self._leaves)
        self._leaves.append(record_hash)
        snapshot = self._publisher.current_signed_checkpoint()
        proof = self._publisher.inclusion_proof(leaf_index, snapshot)
        anchor_record = anchor(snapshot) if anchor is not None else None
        return ConduitReceipt(
            kind=kind,
            payload=payload,
            record_hash_hex=record_hash,
            leaf_index=leaf_index,
            tree_size=snapshot.checkpoint.tree_size,
            inclusion_proof_hex=proof,
            checkpoint_origin=snapshot.checkpoint.origin,
            checkpoint_root_hex=snapshot.checkpoint.root_hash_hex,
            signed_note=snapshot.signed_note,
            log_key_name=self._publisher.origin,
            log_public_key_b64=self.public_key_b64(),
            anchor=anchor_record,
        )


# --------------------------------------------------------------------------- anchor helper
def make_rfc3161_anchor(
    *,
    authority: str,
    tsa_url: str,
    poster: Poster,
    nonce: int,
    req_policy_oid: str | None = None,
) -> AnchorFn:
    """Build an ``AnchorFn`` that anchors a checkpoint to a real RFC 3161 TSA via
    the injected ``poster`` (a deployment supplies a timeout-bounded HTTP poster;
    tests inject a local one). No network import in this module."""

    def _anchor(snapshot: SignedCheckpoint) -> CheckpointAnchorRecord:
        cp = snapshot.checkpoint
        digest = anchor_subject_digest(cp.origin, cp.tree_size, cp.root_hash)
        response_der = submit_anchor(
            digest, tsa_url=tsa_url, nonce=nonce, poster=poster, req_policy_oid=req_policy_oid
        )
        return CheckpointAnchorRecord.from_response(
            checkpoint=cp,
            signed_note=snapshot.signed_note,
            authority=authority,
            response_der=response_der,
            request_nonce=nonce,
        )

    return _anchor


# --------------------------------------------------------------------------- grant + drift
def grant_payload(grant: DirectoryGrant) -> dict[str, Any]:
    return {"event": ConduitEventKind.GRANT_SEALED.value, **grant.canonical_payload()}


def seal_grant(
    chain: ConduitProvenanceChain,
    grant: DirectoryGrant,
    *,
    anchor: AnchorFn | None = None,
) -> ConduitReceipt:
    """Seal a directory grant as the first receipt — before any agent is read."""
    return chain.seal(ConduitEventKind.GRANT_SEALED, grant_payload(grant), anchor=anchor)


def detect_scope_drift(
    grant: DirectoryGrant, live_scopes: Iterable[str]
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """Compare the live provider scope set to the sealed grant. Returns
    ``(added, removed)`` — silent escalation and silent revocation respectively.
    Empty + empty means the connection is still exactly what was sealed."""
    live = set(canonical_scopes(live_scopes))
    sealed = set(grant.granted_scopes)
    added = tuple(sorted(live - sealed))
    removed = tuple(sorted(sealed - live))
    return added, removed


def drift_payload(
    grant: DirectoryGrant, added: tuple[str, ...], removed: tuple[str, ...]
) -> dict[str, Any]:
    return {
        "event": ConduitEventKind.CONNECTION_DRIFT.value,
        "grant_id": str(grant.grant_id),
        "provider": grant.provider.value,
        "tenant_id": grant.tenant_id,
        "sealed_granted_scopes": list(grant.granted_scopes),
        "scopes_added": list(added),
        "scopes_removed": list(removed),
        "observed_at": datetime.now(UTC).isoformat(),
    }


class ConnectionDriftError(ConnectorError):
    """Raised when the live scope set diverges from the sealed grant. The scan
    is refused (fail-closed) and a ``CONNECTION_DRIFT`` fact is sealed."""


class DriftGuardedConnector(BaseConnector):
    """
    Wraps a connector so it refuses to scan when the connection's live scope set
    no longer matches the sealed grant — sealing a ``CONNECTION_DRIFT`` receipt
    and raising ``ConnectionDriftError``. A self-auditing connection: silent
    escalation or revocation fails the scan closed instead of reading on stale
    consent.
    """

    def __init__(
        self,
        *,
        inner: BaseConnector,
        grant: DirectoryGrant,
        live_scopes: Callable[[], Iterable[str]],
        chain: ConduitProvenanceChain,
        anchor: AnchorFn | None = None,
    ) -> None:
        super().__init__(source=inner.source, name=f"drift_guarded:{inner.name}")
        self._inner = inner
        self._grant = grant
        self._live_scopes = live_scopes
        self._chain = chain
        self._anchor = anchor
        self.last_drift_receipt: ConduitReceipt | None = None

    def _run_scan(self, context: ConnectorContext):
        added, removed = detect_scope_drift(self._grant, self._live_scopes())
        if added or removed:
            self.last_drift_receipt = self._chain.seal(
                ConduitEventKind.CONNECTION_DRIFT,
                drift_payload(self._grant, added, removed),
                anchor=self._anchor,
            )
            raise ConnectionDriftError(
                f"connection scope drift on {self._grant.provider.value} "
                f"tenant={self._grant.tenant_id}: added={added} removed={removed}; "
                "refusing to scan on stale consent"
            )
        yield from self._inner.scan(context)


# --------------------------------------------------------------------------- inventory
def candidate_digest(candidate: CandidateAgent) -> str:
    """A deterministic per-agent leaf: the agent's identity + risk + sealed
    blast radius. Two scans of the same agent in the same posture hash the same;
    any change to its reach or band changes the leaf."""
    payload = {
        "reconciliation_key": candidate.reconciliation_key,
        "source": candidate.source.value,
        "external_id": candidate.external_id,
        "risk_band": candidate.risk_band.value,
        "scopes": candidate.evidence.get("scopes"),
        "blast_radius": candidate.evidence.get("blast_radius"),
    }
    return record_hash_of(payload)


def inventory_merkle_root(candidates: Iterable[CandidateAgent]) -> str:
    """Merkle root over the SORTED set of per-agent leaves — order-independent,
    so the root commits to the exact set of agents (and their posture) at time
    T, not the scan order."""
    leaves = sorted(candidate_digest(c) for c in candidates)
    return merkle_root(leaves) if leaves else _EMPTY_TREE_ROOT


def inventory_payload(tenant_id: str, candidates: list[CandidateAgent]) -> dict[str, Any]:
    leaves = sorted(candidate_digest(c) for c in candidates)
    keys = sorted(c.reconciliation_key for c in candidates)
    return {
        "event": ConduitEventKind.INVENTORY_SNAPSHOT_SEALED.value,
        "tenant_id": tenant_id.strip().casefold(),
        "agent_count": len(leaves),
        "inventory_merkle_root": merkle_root(leaves) if leaves else _EMPTY_TREE_ROOT,
        "agent_leaf_digests": leaves,
        "agent_keys": keys,
        "sealed_at": datetime.now(UTC).isoformat(),
    }


class InventorySnapshotSealer:
    """
    Seals an ``INVENTORY_SNAPSHOT_SEALED`` receipt — a Merkle root over the
    exact set of agents that existed in a tenant at epoch T, externally
    anchored. "Here is precisely the estate your directory held at this instant."

    Anchoring is **batched** (``anchor_every``) so churny estates don't make an
    unbounded number of TSA calls: every snapshot is sealed + signed (cheap,
    in-process), but only every Nth snapshot pays the external RFC 3161 anchor.
    """

    def __init__(
        self,
        chain: ConduitProvenanceChain,
        *,
        anchor: AnchorFn | None = None,
        anchor_every: int = 1,
    ) -> None:
        if anchor_every < 1:
            raise ValueError("anchor_every must be >= 1")
        self._chain = chain
        self._anchor = anchor
        self._anchor_every = anchor_every
        self._sealed_count = 0

    def seal(self, tenant_id: str, candidates: list[CandidateAgent]) -> ConduitReceipt:
        payload = inventory_payload(tenant_id, candidates)
        # Batch the expensive external anchor; always seal+sign in-process.
        use_anchor = self._anchor if (self._sealed_count % self._anchor_every == 0) else None
        receipt = self._chain.seal(
            ConduitEventKind.INVENTORY_SNAPSHOT_SEALED, payload, anchor=use_anchor
        )
        self._sealed_count += 1
        return receipt


# --------------------------------------------------------------------------- standing watch
@dataclass(frozen=True, slots=True)
class WatchTick:
    """The result of one standing-watch delta sweep."""

    changed_count: int
    candidate_count: int
    receipt: ConduitReceipt | None  # a fresh sealed snapshot, or None if nothing changed


class StandingWatch:
    """
    Bridges a connector's ``sweep_delta()`` to a re-sealed inventory snapshot —
    closing the standing-watch gap where ``sweep_delta`` returned raw dicts wired
    to nothing.

    On each delta sweep: if the provider reports changed principals, re-scan the
    estate into ``CandidateAgent`` records and seal a FRESH inventory snapshot.
    Each inventory-changing delta thus produces a new externally-anchorable
    snapshot, making the continuity un-backfillable. (The core
    ``BackgroundScanScheduler`` is left untouched; this is the conduit-side
    bridge a deployment hands the scheduler as its per-tenant sweep callback.)
    """

    def __init__(
        self,
        *,
        connector: BaseConnector,
        sealer: InventorySnapshotSealer,
        context: ConnectorContext,
    ) -> None:
        self._connector = connector
        self._sealer = sealer
        self._context = context

    def full_scan_and_seal(self) -> WatchTick:
        candidates = list(self._connector.scan(self._context))
        receipt = self._sealer.seal(self._context.tenant_id, candidates)
        return WatchTick(changed_count=len(candidates), candidate_count=len(candidates), receipt=receipt)

    def on_delta(self) -> WatchTick:
        sweep = getattr(self._connector, "sweep_delta", None)
        changed = list(sweep()) if callable(sweep) else []
        if not changed:
            return WatchTick(changed_count=0, candidate_count=0, receipt=None)
        # A change was reported — re-scan into CandidateAgents (NOT raw dicts)
        # and seal a fresh snapshot.
        candidates = list(self._connector.scan(self._context))
        receipt = self._sealer.seal(self._context.tenant_id, candidates)
        return WatchTick(
            changed_count=len(changed), candidate_count=len(candidates), receipt=receipt
        )
