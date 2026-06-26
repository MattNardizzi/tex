"""Taint-Gated Mint (TG-PCC B1+) — the agent-INDEPENDENT integrity-label source
the mint-gate consults before the broker signs.

The locked B1+ design gates the MINT on a verified integrity label: an action
whose operands derive from UNTRUSTED / quarantined data is *structurally* unable
to obtain a token — the label is a PRECONDITION OF THE SIGNATURE EXISTING, not a
guard consulted after signing.

THE HONESTY PROBLEM THIS MODULE SOLVES
--------------------------------------
A label is only meaningful if its source is AGENT-INDEPENDENT. If the only
available label were one the calling agent asserts about itself (e.g. a
``trusted=true`` request field, or a label derived from the agent's own free-text
``content``), the gate would be decorative: the agent would simply claim
"trusted", and UNTRUSTED content would launder itself to TRUSTED at issuance.

The ground-truth reads are DECISIVE: there is NO in-process, agent-independent
integrity-label producer on the standing ``/v1/govern/mint`` -> ``decide()`` path
today.

  * ``decide()`` / ``DecisionOutcome`` carry no integrity/taint/provenance label
    (only ``decision_id`` / ``evidence_hash``, which are audit identifiers, not
    labels).
  * The CaMeL/FIDES interpreter (``tex.camel``) IS a real agent-independent label
    engine — a value's integrity is bound by the interpreter from the plan-node
    type and source key, never declared by the agent — but it is NEVER invoked on
    the live ``decide()`` path (the ``CamelSpecialist`` abstains: no ``camel_plan``
    metadata is ever produced), and its result is a fused risk score, not a
    preserved label.
  * The IFC engine's label is classified from the REQUEST FIELDS (``content`` is
    labelled ``USER_INPUT`` — the caller's own text), so feeding ``body.content``
    into it is agent self-attestation.

THE HONEST MECHANISM (and its ledgered ceiling)
-----------------------------------------------
Because no agent-independent label is produced *in band* on this path, the label
must be supplied by a **trusted label producer DISTINCT from the calling agent**
— the in-path PEP / CaMeL interpreter / quarantine store that actually observed
the operands' provenance. That producer stamps a ``ProvenanceCommitment`` (the
FIDES dual-axis label of the operand meet, the policy floor, a Merkle
``lineage_root`` over the operand DAG, and a ``label_id``) and SIGNS it with an
operator-held producer secret (``TEX_TAINT_LABEL_SECRET``).

The mint route VERIFIES that signature with the SAME operator secret before it
will mint. The calling agent cannot forge the commitment because it does not hold
the producer secret — so it cannot raise its own integrity. This is the genuine
agent-independence: the floor is operator code (uncontrollable by the caller) and
the label is a producer-signed attestation (unforgeable by the caller).

LEDGERED CEILING (state plainly; never claim away):

  * **The label assessor is in the TCB.** The integrity label is only as sound as
    the trusted producer that stamped it; this gate moves the trust to that
    producer, it does not eliminate it. If the producer mis-labels a quarantined
    operand as TRUSTED, the floor check passes wrongly.
  * **Residual confused-deputy within already-trusted operands.** The gate closes
    UNTRUSTED-derivation; it does not adjudicate misuse among operands all of
    which are legitimately trusted.
  * ``lineage_root`` is a COMMITMENT, not the DAG. An offline verifier proves the
    signature binds the committed label/floor and that ``label ⊒ floor``; it does
    NOT re-derive the label from raw operands without also being handed the
    operand records.
  * Confidentiality covert channels are out of scope. No in-path kill without a
    Body (Render = Decide + Prove). Beyond-frontier ONLY on the
    integrity/untrusted-derivation vector; parity elsewhere.

The label is represented on the CaMeL/FIDES integrity axis (lower int = MORE
trusted: ``TRUSTED=0 < USER=1 < UNTRUSTED=2``; join = max, "most-tainted wins").
``label ⊒ floor`` (the label dominates / is no-more-tainted-than the floor) is the
check ``int(label.integrity) <= int(floor.integrity)``.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from dataclasses import dataclass
from typing import Any, Iterable

from tex.camel.capability import (
    CapabilityLevel,
    CapabilitySet,
    ConfidentialityLevel,
    FidesLabel,
)
from tex.c2pa.cosign_context_tree import MerkleLeaf, _canonical_json, merkle_root

__all__ = [
    "ProvenanceCommitment",
    "OperandNode",
    "compute_lineage_root",
    "meet_label",
    "fides_label_to_prov_dict",
    "prov_commit_dict",
    "sign_label_envelope",
    "verify_label_envelope",
    "label_producer_secret",
    "PROV_COMMIT_ENC",
    "label_dominates_floor",
    "PdpIntegrityLabel",
    "map_ifc_integrity_to_camel",
    "map_ifc_confidentiality",
    "build_pdp_commitment",
]

# The encoding tag stamped into every prov_commit so an offline verifier knows
# which numeric direction the integers use (CaMeL: TRUSTED=0 low-taint, join=max)
# and therefore which comparison (``<=``) is the ⊒-floor predicate. The IFC engine
# uses the INVERSE encoding — never serialize bare ints without this tag.
PROV_COMMIT_ENC = "camel.fides.v1"

# Domain separation for the producer's HMAC over the label envelope. Distinct
# from the credential's ``texauth.v1`` domain so a label signature can never be
# replayed as a credential signature or vice-versa.
_LABEL_DOMAIN = "tex-taint-label.v1"


# --------------------------------------------------------------------------- #
# Operand DAG -> lineage_root                                                  #
# --------------------------------------------------------------------------- #


@dataclass(frozen=True, slots=True)
class OperandNode:
    """One node of the operand provenance DAG the action's operands derive from.

    ``node_id`` is a stable id; ``label_id`` is the opaque provenance-record key;
    ``integrity`` / ``confidentiality`` are the FIDES levels the trusted producer
    assigned this operand; ``parents`` are the node_ids of its direct ancestors
    (so the Merkle leaf commits to the EDGES, a DAG commitment, not just a set).
    """

    node_id: str
    label_id: str
    integrity: CapabilityLevel
    confidentiality: ConfidentialityLevel
    parents: tuple[str, ...] = ()


def compute_lineage_root(nodes: Iterable[OperandNode]) -> str:
    """A tamper-evident Merkle commitment over the operand DAG (64-hex SHA-256).

    Reuses the offline, domain-separated, pure-SHA-256 ``cosign_context_tree``
    Merkle (NOT the BN254/Poseidon zkprov one — that is circuit-coupled and not
    offline-friendly). Nodes are sorted by ``node_id`` for a deterministic leaf
    order; each leaf folds in the node's label + sorted parent ids so the root
    commits to the dependency structure.
    """
    materialized = sorted(nodes, key=lambda n: n.node_id)
    if not materialized:
        # No operands => nothing to commit. The empty DAG is its own stable
        # sentinel root; the floor check (which fails closed) is the real guard.
        return hashlib.sha256(b"tex-taint-label:empty-dag").hexdigest()
    leaves = [
        MerkleLeaf(
            label="lineage.operand",
            value_json=_canonical_json(
                {
                    "id": n.node_id,
                    "label_id": n.label_id,
                    "integrity": int(n.integrity),
                    "confidentiality": int(n.confidentiality),
                    "parents": sorted(n.parents),
                }
            ),
        )
        for n in materialized
    ]
    return merkle_root(leaves).hex()


def meet_label(nodes: Iterable[OperandNode]) -> FidesLabel:
    """The integrity MEET (least-trusted ancestor wins) + confidentiality
    high-water-mark over the operand DAG, via the CaMeL ``CapabilitySet`` algebra.

    The meet is the high-water-mark join (``max`` on the inverse-encoded integrity
    axis) — a derived operand inherits the lowest trust of ANY ancestor. An empty
    operand set is NOT treated as TRUSTED here: the caller's gate fails closed on
    an empty/absent commitment; this helper only computes the meet of what IS
    present.
    """
    caps = CapabilitySet.empty()
    for n in nodes:
        from tex.camel.capability import Capability

        caps = caps.add(
            Capability(
                level=n.integrity,
                confidentiality=n.confidentiality,
                source=n.label_id or "operand",
                provenance_id=n.node_id,
            )
        )
    return caps.fides_label


# --------------------------------------------------------------------------- #
# prov_commit serialization (the signed-body recipe)                          #
# --------------------------------------------------------------------------- #


def fides_label_to_prov_dict(label: FidesLabel) -> dict[str, int]:
    """Serialize a FIDES label as the fixed-key integer dict prov_commit carries.

    Integers (not enum names) under the ``camel.fides.v1`` encoding so the bytes
    are stable and the verifier applies the correct ``<=`` direction.
    """
    return {
        "integrity": int(label.integrity),
        "confidentiality": int(label.confidentiality),
    }


def label_dominates_floor(label: FidesLabel, floor: FidesLabel) -> bool:
    """The ⊒ predicate under the CaMeL encoding (lower int = more trusted).

    ``label ⊒ floor`` holds iff the label is no MORE tainted than the floor on
    integrity AND no MORE sensitive than the floor allows on confidentiality —
    i.e. ``int(label.integrity) <= int(floor.integrity)`` and likewise for
    confidentiality.
    """
    return (
        int(label.integrity) <= int(floor.integrity)
        and int(label.confidentiality) <= int(floor.confidentiality)
    )


@dataclass(frozen=True, slots=True)
class ProvenanceCommitment:
    """A trusted-producer-signed provenance commitment for an action's operands.

    This is the agent-independent label the mint-gate consults. It carries the
    operand meet ``label``, the policy ``floor``, the ``lineage_root`` Merkle
    commitment over the operand DAG, and the opaque ``label_id``. ``aud`` / ``act``
    bind the commitment to a specific (audience, action) so a label minted for one
    action cannot be replayed onto another.
    """

    label: FidesLabel
    floor: FidesLabel
    lineage_root: str
    label_id: str
    aud: str
    act: str

    def to_prov_commit(self) -> dict[str, Any]:
        """The fixed-key dict embedded INTO the signed credential claims."""
        return {
            "enc": PROV_COMMIT_ENC,
            "label": fides_label_to_prov_dict(self.label),
            "floor": fides_label_to_prov_dict(self.floor),
            "lineage_root": self.lineage_root,
            "label_id": self.label_id,
        }

    def dominates_floor(self) -> bool:
        return label_dominates_floor(self.label, self.floor)


def prov_commit_dict(commit: ProvenanceCommitment) -> dict[str, Any]:
    """Convenience: the embeddable prov_commit dict for a commitment."""
    return commit.to_prov_commit()


# --------------------------------------------------------------------------- #
# Producer signing / verification (the agent-independence boundary)           #
# --------------------------------------------------------------------------- #


def label_producer_secret() -> str | None:
    """The operator-held label-producer secret (``TEX_TAINT_LABEL_SECRET``).

    Returns None when unset — so a flag-on mint with NO producer secret FAILS
    CLOSED (it cannot verify any label and therefore refuses). There is no
    guessable default: a default secret would let the agent itself produce a
    valid-looking label, defeating agent-independence.
    """
    secret = os.environ.get("TEX_TAINT_LABEL_SECRET", "").strip()
    return secret or None


def _envelope_body(commit: ProvenanceCommitment) -> str:
    """The canonical bytes the producer HMAC covers — label + floor + lineage +
    (aud, act) binding, domain-separated and key-sorted."""
    payload = {
        "domain": _LABEL_DOMAIN,
        "enc": PROV_COMMIT_ENC,
        "label": fides_label_to_prov_dict(commit.label),
        "floor": fides_label_to_prov_dict(commit.floor),
        "lineage_root": commit.lineage_root,
        "label_id": commit.label_id,
        "aud": commit.aud,
        "act": commit.act,
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def sign_label_envelope(commit: ProvenanceCommitment, *, secret: str) -> str:
    """The trusted producer's HMAC-SHA256 over the commitment (hex).

    Only a holder of the operator producer secret can produce this — that is what
    makes the label agent-independent. (Test/producer-side helper; the agent on
    the mint path never calls this.)
    """
    return hmac.new(
        secret.encode("utf-8"), _envelope_body(commit).encode("utf-8"), hashlib.sha256
    ).hexdigest()


def verify_label_envelope(
    commit: ProvenanceCommitment, signature: str, *, secret: str
) -> bool:
    """Constant-time verify of a producer-signed commitment. Fail-closed on any
    defect (malformed, wrong key, missing signature)."""
    if not signature or not secret:
        return False
    try:
        expected = sign_label_envelope(commit, secret=secret)
    except Exception:  # noqa: BLE001 — any serialization defect fails closed
        return False
    return hmac.compare_digest(expected, str(signature))


# --------------------------------------------------------------------------- #
# LIVE PDP label producer (TG-PCC B1+) — Tex's own, agent-INDEPENDENT label     #
#                                                                              #
# This is the in-process producer that makes Tex's PDP — NOT the calling agent  #
# — the source of the integrity label the E2 mint-gate consults. The signal it  #
# rides on is the IfcSpecialist's per-request label (response.metadata[         #
# 'ifc_labels']), which Tex's own classifier assigns from the SOURCE TYPE it    #
# determines (default request.content => USER_INPUT; operator/PEP-set metadata  #
# markers drop it to TOOL_UNTRUSTED / lift it to TOOL_TRUSTED; retrieved policy #
# clauses => SYS_INSTR). The agent puts text in body.content but cannot tell    #
# the classifier that text is trusted — the markers are EvaluationRequest.      #
# metadata keys, never MintRequest body fields, and the bare standing path      #
# passes none — which is exactly what keeps this label agent-independent.       #
#                                                                              #
# GRANULARITY CEILING (state plainly; do NOT claim away): this is a SINGLE-     #
# REQUEST SOURCE classification, strictly COARSER than full operand-lineage. It #
# CANNOT catch an injection laundered as trusted-looking USER_INPUT, because    #
# that needs a multi-hop operand DAG which only exists when the agent runs      #
# through the CaMeL/FIDES interpreter (NOT on the decide()/mint path). The      #
# ``lineage_root`` here is a degenerate single-node commitment over the PDP-    #
# named decision edge, not a reconstructed operand DAG. The label assessor is   #
# in the TCB — this moves trust into Tex's own classifier + in-process signing, #
# it does not eliminate trust.                                                  #
# --------------------------------------------------------------------------- #


@dataclass(frozen=True, slots=True)
class PdpIntegrityLabel:
    """The agent-independent integrity label Tex's PDP derived for one ruling.

    Carried in-process on ``DecisionOutcome.integrity_label`` (never serialized,
    exactly like ``response`` / ``forbid_scope``) so the mint route can build a
    self-signed ``ProvenanceCommitment`` from it WITHOUT reading any caller field.

    ``integrity`` / ``confidentiality`` are on the CaMeL/FIDES axis the gate's
    floor uses. ``label_id`` is ``pdp:{decision_id}:{evidence_hash}`` — it binds
    the label to the exact PDP ruling, both being Tex-minted audit ids the caller
    cannot forge. ``source`` is the IFC integrity enum NAME it was derived from;
    ``basis`` is a short human reason for the audit trail.
    """

    integrity: CapabilityLevel
    confidentiality: ConfidentialityLevel
    label_id: str
    source: str
    basis: str


# IFC IntegrityLevel NAME -> CaMeL CapabilityLevel. The two lattices run in
# OPPOSITE numeric directions (IFC: higher int = more trusted, join=min; CaMeL:
# lower int = more trusted, join=max — see PROV_COMMIT_ENC note above), so the
# mapping MUST be by enum NAME, never a bare int passthrough. Conservative:
#   * SYS_INSTR (operator-authored root of trust)      -> TRUSTED (0)
#   * TOOL_TRUSTED (trusted-but-not-authoritative)     -> USER (1)  [never TRUSTED]
#   * USER_INPUT (direct user text)                    -> USER (1)  [partially trusted]
#   * TOOL_UNTRUSTED (external/tool output)            -> UNTRUSTED (2)
#   * TOOL_DESC (most attacker-controllable)           -> UNTRUSTED (2)
#   * anything unrecognized / absent                   -> UNTRUSTED (2)  [fail-closed]
# NOTE the non-circularity: USER_INPUT -> USER does NOT dominate the default
# TRUSTED floor, so a bare free-text mint REFUSES rather than laundering the
# agent's own content as TRUSTED. A label reaches TRUSTED only from an
# operator-controlled signal (SYS_INSTR), which the agent does not control.
_IFC_INTEGRITY_TO_CAMEL: dict[str, CapabilityLevel] = {
    "SYS_INSTR": CapabilityLevel.TRUSTED,
    "TOOL_TRUSTED": CapabilityLevel.USER,
    "USER_INPUT": CapabilityLevel.USER,
    "TOOL_UNTRUSTED": CapabilityLevel.UNTRUSTED,
    "TOOL_DESC": CapabilityLevel.UNTRUSTED,
}

# IFC ConfidentialityLevel NAME -> CaMeL ConfidentialityLevel. Both lattices use
# the SAME direction and the SAME names (PUBLIC=0 < INTERNAL=1 < CONFIDENTIAL=2
# < RESTRICTED=3), so this is a NAME->NAME 1:1. Unknown/absent fails closed to
# RESTRICTED (most sensitive — refused under any non-RESTRICTED floor).
_IFC_CONF_TO_CAMEL: dict[str, ConfidentialityLevel] = {
    "PUBLIC": ConfidentialityLevel.PUBLIC,
    "INTERNAL": ConfidentialityLevel.INTERNAL,
    "CONFIDENTIAL": ConfidentialityLevel.CONFIDENTIAL,
    "RESTRICTED": ConfidentialityLevel.RESTRICTED,
}


def map_ifc_integrity_to_camel(name: Any) -> CapabilityLevel:
    """Map an IFC integrity enum NAME to the CaMeL integrity axis (fail-closed).

    Unknown / absent / non-string => UNTRUSTED (the least-trusted level) so a
    label Tex cannot positively classify never raises the gate.
    """
    if not isinstance(name, str):
        return CapabilityLevel.UNTRUSTED
    return _IFC_INTEGRITY_TO_CAMEL.get(name.strip().upper(), CapabilityLevel.UNTRUSTED)


def map_ifc_confidentiality(name: Any) -> ConfidentialityLevel:
    """Map an IFC confidentiality enum NAME to the CaMeL axis (fail-closed).

    Unknown / absent / non-string => RESTRICTED (the most-sensitive level) so an
    unclassifiable confidentiality is treated as the most-protected, never waved
    through as PUBLIC.
    """
    if not isinstance(name, str):
        return ConfidentialityLevel.RESTRICTED
    return _IFC_CONF_TO_CAMEL.get(name.strip().upper(), ConfidentialityLevel.RESTRICTED)


def build_pdp_commitment(
    pdp_label: PdpIntegrityLabel,
    *,
    floor: FidesLabel,
    aud: str,
    act: str,
) -> ProvenanceCommitment:
    """Build the agent-independent ProvenanceCommitment from a PDP-derived label.

    The ``lineage_root`` is an HONEST single-node commitment over the one PDP-
    named source (the decision edge), NOT a reconstructed operand DAG — see the
    granularity-ceiling note on this module. The caller (the mint route in LIVE
    mode) SELF-SIGNS the returned commitment with ``label_producer_secret()`` in
    process; no caller-presented field is read.
    """
    label = FidesLabel(
        integrity=pdp_label.integrity,
        confidentiality=pdp_label.confidentiality,
    )
    lineage_root = compute_lineage_root(
        [
            OperandNode(
                node_id="pdp.decision",
                label_id=pdp_label.label_id,
                integrity=pdp_label.integrity,
                confidentiality=pdp_label.confidentiality,
            )
        ]
    )
    return ProvenanceCommitment(
        label=label,
        floor=floor,
        lineage_root=lineage_root,
        label_id=pdp_label.label_id,
        aud=aud,
        act=act,
    )
