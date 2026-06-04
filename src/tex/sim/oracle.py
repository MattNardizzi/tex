"""
oracle.py — where it breaks.

A fish tank only becomes a test when something asserts. For every action the
estate fires, the oracle already knows what *should* happen and checks that it
did — on both sides of the wire:

  backend   — the PDP issued the expected verdict; a decision was sealed; the
              evidence bundle hash-chains; the agent is resolvable.
  interface — "show me any agent / prove it" round-trips: the evidence hash
              returned by /evaluate reappears in the sealed bundle (the true
              SHA-256 the proof layer reveals), and the vigil is speaking.

Each check yields a Check(pass/fail/skip, detail). The runner collects them
into a Report. A failed check is not an error to swallow — it is the product.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from tex.sim.behavior import PlannedAction
from tex.sim.client import TexClient, TexClientError

PASS = "PASS"
FAIL = "FAIL"
SKIP = "SKIP"


@dataclass
class Check:
    name: str
    status: str
    detail: str = ""
    context: dict[str, Any] = field(default_factory=dict)


# --------------------------------------------------------------------------- #
#  Per-action checks                                                          #
# --------------------------------------------------------------------------- #

def check_verdict(planned: PlannedAction, response: dict) -> Check:
    actual = response.get("verdict")
    expected = planned.intended_verdict
    ctx = {
        "agent": planned.agent.external_id,
        "profile": planned.profile,
        "content": planned.content,
        "expected": expected,
        "actual": actual,
        "decision_id": response.get("decision_id"),
        "reasons": response.get("reasons"),
    }
    if actual == expected:
        return Check(f"verdict[{planned.seq}]", PASS, f"{expected} as expected", ctx)
    return Check(f"verdict[{planned.seq}]", FAIL,
                 f"expected {expected}, got {actual} ({planned.profile})", ctx)


def check_sealed(planned: PlannedAction, response: dict) -> Check:
    did = response.get("decision_id")
    ehash = response.get("evidence_hash")
    if did and ehash:
        return Check(f"sealed[{planned.seq}]", PASS, f"decision {did[:8]} sealed @ {ehash[:12]}…",
                     {"decision_id": did, "evidence_hash": ehash})
    if did and not ehash:
        return Check(f"sealed[{planned.seq}]", FAIL,
                     "decision returned but evidence_hash is null (nothing to prove)",
                     {"decision_id": did})
    return Check(f"sealed[{planned.seq}]", FAIL, "no decision_id returned", {"response_keys": list(response.keys())})


def check_proof_roundtrip(client: TexClient, planned: PlannedAction, response: dict) -> Check:
    """The client question loop: pull the sealed bundle and confirm the hash
    the API handed back is the one inside the proof. This is "prove it"."""
    did = response.get("decision_id")
    ehash = response.get("evidence_hash")
    if not did:
        return Check(f"proof[{planned.seq}]", SKIP, "no decision to prove")
    try:
        bundle = client.evidence_bundle(did)
    except TexClientError as e:
        return Check(f"proof[{planned.seq}]", FAIL, f"evidence-bundle {e.status}: {e.body[:120]}",
                     {"decision_id": did})
    blob = str(bundle)
    found = bool(ehash) and ehash in blob
    # Verify intra-bundle hash chaining if the shape exposes it.
    chained = _chain_links_ok(bundle)
    detail = []
    if found:
        detail.append("evidence_hash present in sealed bundle")
    elif ehash:
        detail.append("evidence_hash NOT found in bundle")
    if chained is True:
        detail.append("hash chain links verified")
    elif chained is False:
        detail.append("hash chain link MISMATCH")
    status = PASS if (found and chained is not False) else FAIL
    return Check(f"proof[{planned.seq}]", status, "; ".join(detail) or "bundle returned",
                 {"decision_id": did, "evidence_hash": ehash})


def _chain_links_ok(bundle: Any) -> bool | None:
    """Best-effort hash-chain verification. Returns True/False if the bundle
    exposes ordered records with hash/previous_hash, else None (shape unknown)."""
    records = None
    if isinstance(bundle, dict):
        for key in ("records", "evidence", "chain", "entries", "evidence_records"):
            if isinstance(bundle.get(key), list):
                records = bundle[key]
                break
    if not records or len(records) < 2:
        return None
    prev_hash = None
    for r in records:
        if not isinstance(r, dict):
            return None
        h = r.get("hash") or r.get("sha256") or r.get("record_hash")
        ph = r.get("previous_hash") or r.get("prev_hash")
        if prev_hash is not None and ph is not None and ph != prev_hash:
            return False
        prev_hash = h if h is not None else prev_hash
    return True


# --------------------------------------------------------------------------- #
#  Discovery + inventory checks (the "mapping" oracle)                        #
# --------------------------------------------------------------------------- #

def check_inventory(client: TexClient, expected_total: int, expected_shadow: int) -> list[Check]:
    out: list[Check] = []
    try:
        agents = client.list_agents()
    except TexClientError as e:
        return [Check("inventory.list", FAIL, f"/v1/agents {e.status}: {e.body[:120]}")]
    items = _as_list(agents)
    out.append(Check("inventory.count", PASS if items else FAIL,
                     f"{len(items)} agents discovered (estate seeded {expected_total})",
                     {"discovered": len(items), "expected": expected_total}))
    # Shadow agents should be present (caught by audit, not the directory).
    blob = str(agents)
    shadow_hits = blob.count("shadow") + blob.count("cloud_audit")
    out.append(Check("inventory.shadow_caught", PASS if shadow_hits else SKIP,
                     f"shadow/audit-plane signal present in inventory" if shadow_hits
                     else "no obvious shadow marker in inventory shape",
                     {"shadow_signal": shadow_hits, "expected_shadow": expected_shadow}))
    # Prove one agent: resolve + pull its ledger (the "show me any agent" loop).
    if items:
        aid = _agent_id(items[0])
        if aid:
            try:
                client.get_agent(aid)
                out.append(Check("inventory.resolve_one", PASS, f"agent {aid[:12]} resolvable"))
            except TexClientError as e:
                out.append(Check("inventory.resolve_one", FAIL, f"get_agent {e.status}"))
    return out


def check_voice(client: TexClient) -> Check:
    try:
        v = client.vigil()
    except TexClientError as e:
        return Check("voice.vigil", FAIL, f"/v1/vigil {e.status}: {e.body[:120]}")
    utter = v.get("utterances") or []
    standing = v.get("standing")
    return Check("voice.vigil", PASS if (utter or standing) else SKIP,
                 f"standing={standing}, {len(utter)} utterance(s) chosen",
                 {"selector_version": (v.get("meta") or {}).get("selector_version")})


def check_chain_integrity(client: TexClient) -> Check:
    try:
        s = client.system_state()
    except TexClientError as e:
        return Check("integrity.chain", FAIL, f"/v1/system/state {e.status}")

    chain = s.get("chain") if isinstance(s, dict) else None
    if not isinstance(chain, dict):
        # Shape unknown — don't guess from substrings; report that we couldn't
        # locate the integrity flags rather than inventing a faltering signal.
        return Check("integrity.chain", SKIP, "no chain block in /v1/system/state",
                     {"keys": list(s.keys()) if isinstance(s, dict) else None})

    # Only the integrity flags themselves decide this — unrelated False fields
    # (durable_persistence, drift_durable, ...) must not trip it.
    flags = {k: v for k, v in chain.items() if k.endswith("_intact")}
    broken = [k for k, v in flags.items() if v is False]
    if broken:
        return Check("integrity.chain", FAIL,
                     f"chain integrity broken: {', '.join(broken)} (faltering condition)",
                     {"chain": chain})
    if not flags:
        return Check("integrity.chain", SKIP, "no *_intact flags present", {"chain": chain})
    detail = ", ".join(f"{k}={v}" for k, v in flags.items())
    length = chain.get("discovery_ledger_length")
    return Check("integrity.chain", PASS,
                 f"chain intact ({detail}" + (f", ledger={length}" if length is not None else "") + ")",
                 {"chain": chain})


def _as_list(payload: Any) -> list:
    if isinstance(payload, list):
        return payload
    if isinstance(payload, dict):
        for k in ("agents", "items", "results", "data"):
            if isinstance(payload.get(k), list):
                return payload[k]
    return []


def _agent_id(item: Any) -> str | None:
    if isinstance(item, dict):
        for k in ("agent_id", "id", "uuid", "external_id"):
            if item.get(k):
                return str(item[k])
    return None
