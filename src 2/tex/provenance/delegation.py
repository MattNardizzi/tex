"""
Sealed delegation graph — the agent-to-agent dark zone, witnessed.

Discovery products map nodes: a list of agents. Tex maps *edges* — who
delegates to whom — because the edge is where blast radius lives. When an
agent hands work to another agent (an A2A call, an MCP that is itself an
agent, a sub-agent invocation), that delegation is the path a compromise
travels. Nobody seals it, so nobody can prove, after the fact, that agent
A was load-bearing for agent B.

This module seals each observed delegation edge into an append-only,
hash-chained, ECDSA-signed log — the same Certificate-Transparency shape
as the behavioural provenance ledger. Two properties fall out of that:

  * A relying party can verify the delegation graph offline, holding only
    the public key — the edges are evidence, not a mutable adjacency
    table someone has to trust.
  * The dormancy controller can ask a defensible question before it
    sleeps an idle agent: *does anything delegate to this one?* An agent
    with a sealed incoming edge is load-bearing as far as Tex can prove,
    and the doctrine forbids sleeping it silently — uncertainty there is a
    genuine ABSTAIN, not a quiet retirement.

Edges carry only structural metadata (the two agent ids, the channel the
delegation rode, a graded confidence). Never content — the same privacy
line the rest of the provenance layer holds.
"""

from __future__ import annotations

import base64
import hashlib
import json
import threading
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from tex.events._ecdsa_provider import default_signature_provider
from tex.pqcrypto.algorithm_agility import SignatureKeyPair, SignatureProvider


def _stable_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str)


def _sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class DelegationEdge:
    """One sealed delegation: ``delegator`` handed work to ``delegate``."""

    sequence: int
    delegator_id: UUID
    delegate_id: UUID
    channel: str
    confidence: float
    observation_count: int
    first_seen_at: datetime
    last_seen_at: datetime

    payload_sha256: str = ""
    previous_hash: str | None = None
    record_hash: str = ""
    signature_b64: str = ""
    signing_key_id: str = ""

    def to_jsonable(self) -> dict[str, Any]:
        return {
            "sequence": self.sequence,
            "delegator_id": str(self.delegator_id),
            "delegate_id": str(self.delegate_id),
            "channel": self.channel,
            "confidence": round(self.confidence, 6),
            "observation_count": self.observation_count,
            "first_seen_at": self.first_seen_at.isoformat(),
            "last_seen_at": self.last_seen_at.isoformat(),
            "record_hash": self.record_hash,
            "previous_hash": self.previous_hash,
            "signature_b64": self.signature_b64,
            "signing_key_id": self.signing_key_id,
        }


@dataclass
class _EdgeState:
    delegator_id: UUID
    delegate_id: UUID
    channel: str
    confidence: float
    observation_count: int
    first_seen_at: datetime
    last_seen_at: datetime
    record_hash: str


class SealedDelegationGraph:
    """
    Append-only, hash-chained, signed log of observed delegation edges,
    with a live adjacency view derived from the sealed records.

    Thread-safe. In-memory by default — the same pattern the other
    ledgers follow; a Postgres mirror layers on without changing this
    contract.
    """

    def __init__(
        self,
        *,
        signing_key: SignatureKeyPair | None = None,
        signing_provider: SignatureProvider | None = None,
    ) -> None:
        self._lock = threading.RLock()
        self._records: list[DelegationEdge] = []
        # (delegator, delegate) -> current edge state
        self._edges: dict[tuple[str, str], _EdgeState] = {}
        # delegate -> set of delegators (the "who depends on me" index)
        self._incoming: dict[str, set[str]] = {}
        self._provider: SignatureProvider = (
            signing_provider or default_signature_provider()
        )
        self._key: SignatureKeyPair = (
            signing_key or self._provider.generate_keypair("tex-delegation-graph")
        )

    @property
    def public_key_pem(self) -> bytes:
        return self._key.public_key

    @property
    def signing_key_id(self) -> str:
        return self._key.key_id

    # ------------------------------------------------------------------ write
    def observe_delegation(
        self,
        *,
        delegator_id: UUID,
        delegate_id: UUID,
        channel: str = "unknown",
        confidence: float = 1.0,
    ) -> DelegationEdge:
        """
        Seal one observed delegation edge. Re-observing an existing edge
        seals a refreshed record (the edge is still live) and bumps its
        observation count; the chain therefore witnesses persistence, not
        just first sighting.
        """
        if delegator_id == delegate_id:
            raise ValueError("an agent cannot delegate to itself")
        key = (str(delegator_id), str(delegate_id))
        with self._lock:
            now = datetime.now(UTC)
            prior = self._edges.get(key)
            first_seen = prior.first_seen_at if prior else now
            obs = (prior.observation_count + 1) if prior else 1

            sequence = len(self._records)
            previous_hash = self._records[-1].record_hash if self._records else None
            payload = {
                "delegator_id": str(delegator_id),
                "delegate_id": str(delegate_id),
                "channel": channel,
                "confidence": round(float(confidence), 6),
                "observation_count": obs,
                "first_seen_at": first_seen.isoformat(),
                "last_seen_at": now.isoformat(),
            }
            payload_json = _stable_json(payload)
            payload_sha256 = _sha256_hex(payload_json)
            record_hash = _sha256_hex(
                _stable_json(
                    {"payload_sha256": payload_sha256, "previous_hash": previous_hash}
                )
            )
            signature = self._provider.sign(record_hash.encode("ascii"), self._key)
            edge = DelegationEdge(
                sequence=sequence,
                delegator_id=delegator_id,
                delegate_id=delegate_id,
                channel=channel,
                confidence=float(confidence),
                observation_count=obs,
                first_seen_at=first_seen,
                last_seen_at=now,
                payload_sha256=payload_sha256,
                previous_hash=previous_hash,
                record_hash=record_hash,
                signature_b64=base64.b64encode(signature).decode("ascii"),
                signing_key_id=self._key.key_id,
            )
            self._records.append(edge)
            self._edges[key] = _EdgeState(
                delegator_id=delegator_id,
                delegate_id=delegate_id,
                channel=channel,
                confidence=float(confidence),
                observation_count=obs,
                first_seen_at=first_seen,
                last_seen_at=now,
                record_hash=record_hash,
            )
            self._incoming.setdefault(str(delegate_id), set()).add(str(delegator_id))
            return edge

    # ------------------------------------------------------------------ read
    def delegators_of(self, agent_id: UUID) -> tuple[UUID, ...]:
        """Agents that delegate *to* ``agent_id`` — the dependents."""
        with self._lock:
            keys = self._incoming.get(str(agent_id), set())
            return tuple(UUID(k) for k in sorted(keys))

    def delegates_of(self, agent_id: UUID) -> tuple[UUID, ...]:
        """Agents that ``agent_id`` delegates to — its downstream reach."""
        with self._lock:
            out = [
                state.delegate_id
                for (delegator, _), state in self._edges.items()
                if delegator == str(agent_id)
            ]
        return tuple(sorted(out, key=str))

    def is_load_bearing(self, agent_id: UUID) -> bool:
        """
        True when at least one other agent is sealed as delegating to this
        one. The dormancy controller uses this as a *defensible* signal:
        an agent something depends on is not safe to sleep in silence.
        """
        with self._lock:
            return bool(self._incoming.get(str(agent_id)))

    def list_records(self) -> tuple[DelegationEdge, ...]:
        with self._lock:
            return tuple(self._records)

    def __len__(self) -> int:
        with self._lock:
            return len(self._records)

    # ------------------------------------------------------------------ verify
    def verify_chain(self) -> dict[str, Any]:
        with self._lock:
            records = list(self._records)
        previous_hash: str | None = None
        for idx, rec in enumerate(records):
            payload = {
                "delegator_id": str(rec.delegator_id),
                "delegate_id": str(rec.delegate_id),
                "channel": rec.channel,
                "confidence": round(float(rec.confidence), 6),
                "observation_count": rec.observation_count,
                "first_seen_at": rec.first_seen_at.isoformat(),
                "last_seen_at": rec.last_seen_at.isoformat(),
            }
            payload_sha256 = _sha256_hex(_stable_json(payload))
            record_hash = _sha256_hex(
                _stable_json(
                    {"payload_sha256": payload_sha256, "previous_hash": previous_hash}
                )
            )
            if (
                rec.previous_hash != previous_hash
                or rec.payload_sha256 != payload_sha256
                or rec.record_hash != record_hash
            ):
                return {"intact": False, "checked": idx, "break_at": idx}
            previous_hash = rec.record_hash
        return {"intact": True, "checked": len(records), "break_at": None}

    def verify_signatures(self, public_key_pem: bytes | None = None) -> dict[str, Any]:
        pub = public_key_pem or self._key.public_key
        with self._lock:
            records = list(self._records)
        for idx, rec in enumerate(records):
            try:
                sig = base64.b64decode(rec.signature_b64.encode("ascii"))
            except Exception:  # noqa: BLE001
                return {"valid": False, "checked": idx, "invalid_at": idx}
            if not self._provider.verify(rec.record_hash.encode("ascii"), sig, pub):
                return {"valid": False, "checked": idx, "invalid_at": idx}
        return {"valid": True, "checked": len(records), "invalid_at": None}
