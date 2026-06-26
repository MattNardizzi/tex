"""Unit tests for the agent-INDEPENDENT taint-label source (TG-PCC B1+):
``tex.authority.taint_label`` + the offline ``verify_prov_commit_floor`` helper.

These pin the label-source primitives in isolation from the HTTP route: the
producer-signed envelope (unforgeable without the operator secret), the
``label ⊒ floor`` predicate under the camel.fides.v1 encoding, the deterministic
Merkle lineage commitment, and the fail-closed offline floor re-check.
"""

from __future__ import annotations

from tex.authority.broker import verify_prov_commit_floor
from tex.authority.taint_label import (
    PROV_COMMIT_ENC,
    OperandNode,
    ProvenanceCommitment,
    compute_lineage_root,
    label_dominates_floor,
    label_producer_secret,
    meet_label,
    sign_label_envelope,
    verify_label_envelope,
)
from tex.camel.capability import CapabilityLevel, ConfidentialityLevel, FidesLabel

SECRET = "operator-held-producer-secret"


def _commit(integrity: CapabilityLevel, conf: ConfidentialityLevel) -> ProvenanceCommitment:
    return ProvenanceCommitment(
        label=FidesLabel(integrity=integrity, confidentiality=conf),
        floor=FidesLabel(
            integrity=CapabilityLevel.TRUSTED, confidentiality=ConfidentialityLevel.PUBLIC
        ),
        lineage_root="abc123",
        label_id="lbl-1",
        aud="vault.acme",
        act="read",
    )


# --------------------------------------------------------------------------- #
# ⊒ floor predicate (camel.fides.v1: lower int = more trusted)                 #
# --------------------------------------------------------------------------- #


def test_label_dominates_floor_directions() -> None:
    floor = FidesLabel(
        integrity=CapabilityLevel.USER, confidentiality=ConfidentialityLevel.INTERNAL
    )
    # TRUSTED and USER both dominate a USER floor; UNTRUSTED does not.
    assert label_dominates_floor(
        FidesLabel(integrity=CapabilityLevel.TRUSTED), floor
    )
    assert label_dominates_floor(
        FidesLabel(
            integrity=CapabilityLevel.USER, confidentiality=ConfidentialityLevel.INTERNAL
        ),
        floor,
    )
    assert not label_dominates_floor(
        FidesLabel(integrity=CapabilityLevel.UNTRUSTED), floor
    )
    # Confidentiality dual: a more-sensitive-than-floor label is also under floor.
    assert not label_dominates_floor(
        FidesLabel(
            integrity=CapabilityLevel.TRUSTED,
            confidentiality=ConfidentialityLevel.RESTRICTED,
        ),
        floor,
    )


def test_commitment_dominates_floor() -> None:
    assert _commit(CapabilityLevel.TRUSTED, ConfidentialityLevel.PUBLIC).dominates_floor()
    assert not _commit(
        CapabilityLevel.UNTRUSTED, ConfidentialityLevel.PUBLIC
    ).dominates_floor()


# --------------------------------------------------------------------------- #
# Producer signature = the agent-independence boundary                         #
# --------------------------------------------------------------------------- #


def test_envelope_signature_verifies_with_right_secret() -> None:
    c = _commit(CapabilityLevel.TRUSTED, ConfidentialityLevel.PUBLIC)
    sig = sign_label_envelope(c, secret=SECRET)
    assert verify_label_envelope(c, sig, secret=SECRET) is True


def test_envelope_signature_rejects_wrong_secret() -> None:
    c = _commit(CapabilityLevel.TRUSTED, ConfidentialityLevel.PUBLIC)
    sig = sign_label_envelope(c, secret=SECRET)
    # An agent that does NOT hold the operator secret cannot forge/verify.
    assert verify_label_envelope(c, sig, secret="agent-guess") is False
    assert verify_label_envelope(c, "deadbeef", secret=SECRET) is False
    assert verify_label_envelope(c, "", secret=SECRET) is False


def test_envelope_binds_aud_act() -> None:
    """A signature for (aud=A, act=read) must NOT verify against (aud=B) — the
    label cannot be replayed onto a different action."""
    c = _commit(CapabilityLevel.TRUSTED, ConfidentialityLevel.PUBLIC)
    sig = sign_label_envelope(c, secret=SECRET)
    other = ProvenanceCommitment(
        label=c.label,
        floor=c.floor,
        lineage_root=c.lineage_root,
        label_id=c.label_id,
        aud="OTHER.aud",
        act=c.act,
    )
    assert verify_label_envelope(other, sig, secret=SECRET) is False


def test_label_producer_secret_unset_is_none(monkeypatch) -> None:
    monkeypatch.delenv("TEX_TAINT_LABEL_SECRET", raising=False)
    assert label_producer_secret() is None
    monkeypatch.setenv("TEX_TAINT_LABEL_SECRET", "  s3cret  ")
    assert label_producer_secret() == "s3cret"


# --------------------------------------------------------------------------- #
# lineage_root — deterministic, DAG-structure-sensitive Merkle commitment       #
# --------------------------------------------------------------------------- #


def test_lineage_root_deterministic_and_order_insensitive() -> None:
    n1 = OperandNode("a", "la", CapabilityLevel.TRUSTED, ConfidentialityLevel.PUBLIC)
    n2 = OperandNode(
        "b", "lb", CapabilityLevel.UNTRUSTED, ConfidentialityLevel.CONFIDENTIAL, parents=("a",)
    )
    r1 = compute_lineage_root([n1, n2])
    r2 = compute_lineage_root([n2, n1])  # input order swapped -> same root
    assert r1 == r2
    assert len(r1) == 64 and all(c in "0123456789abcdef" for c in r1)


def test_lineage_root_changes_with_structure() -> None:
    base = [
        OperandNode("a", "la", CapabilityLevel.TRUSTED, ConfidentialityLevel.PUBLIC),
        OperandNode("b", "lb", CapabilityLevel.UNTRUSTED, ConfidentialityLevel.PUBLIC),
    ]
    # Different parent edge -> different DAG -> different root.
    altered = [
        OperandNode("a", "la", CapabilityLevel.TRUSTED, ConfidentialityLevel.PUBLIC),
        OperandNode(
            "b", "lb", CapabilityLevel.UNTRUSTED, ConfidentialityLevel.PUBLIC, parents=("a",)
        ),
    ]
    assert compute_lineage_root(base) != compute_lineage_root(altered)


def test_meet_floors_to_least_trusted() -> None:
    nodes = [
        OperandNode("a", "la", CapabilityLevel.TRUSTED, ConfidentialityLevel.PUBLIC),
        OperandNode("b", "lb", CapabilityLevel.USER, ConfidentialityLevel.INTERNAL),
        OperandNode("c", "lc", CapabilityLevel.UNTRUSTED, ConfidentialityLevel.CONFIDENTIAL),
    ]
    label = meet_label(nodes)
    assert label.integrity == CapabilityLevel.UNTRUSTED  # least-trusted wins
    assert label.confidentiality == ConfidentialityLevel.CONFIDENTIAL  # high-water


# --------------------------------------------------------------------------- #
# Offline verify_prov_commit_floor — fail-closed                               #
# --------------------------------------------------------------------------- #


def test_floor_check_permits_when_dominates() -> None:
    claims = {
        "prov_commit": ProvenanceCommitment(
            label=FidesLabel(
                integrity=CapabilityLevel.TRUSTED, confidentiality=ConfidentialityLevel.PUBLIC
            ),
            floor=FidesLabel(
                integrity=CapabilityLevel.USER, confidentiality=ConfidentialityLevel.INTERNAL
            ),
            lineage_root="r",
            label_id="l",
            aud="a",
            act="x",
        ).to_prov_commit()
    }
    assert verify_prov_commit_floor(claims).ok is True


def test_floor_check_denies_under_floor() -> None:
    claims = {
        "prov_commit": ProvenanceCommitment(
            label=FidesLabel(integrity=CapabilityLevel.UNTRUSTED),
            floor=FidesLabel(integrity=CapabilityLevel.TRUSTED),
            lineage_root="r",
            label_id="l",
            aud="a",
            act="x",
        ).to_prov_commit()
    }
    chk = verify_prov_commit_floor(claims)
    assert chk.ok is False
    assert chk.reason == "insufficient_integrity"


def test_floor_check_fails_closed_on_missing_or_malformed() -> None:
    assert verify_prov_commit_floor(None).ok is False
    assert verify_prov_commit_floor({}).ok is False
    assert verify_prov_commit_floor({"prov_commit": "nope"}).ok is False
    # Wrong enc => deny (cannot know the numeric direction).
    bad_enc = {"prov_commit": {"enc": "other.v9", "label": {}, "floor": {}}}
    assert verify_prov_commit_floor(bad_enc).ok is False
    # Right enc but malformed label => deny.
    malformed = {
        "prov_commit": {
            "enc": PROV_COMMIT_ENC,
            "label": {"integrity": "x"},
            "floor": {"integrity": 0, "confidentiality": 0},
        }
    }
    assert verify_prov_commit_floor(malformed).ok is False
