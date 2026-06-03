"""Tests for tex.institutional.governance_log."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

import tex.ecosystem  # noqa: F401  prime ordering

from tex.institutional import (
    ControllerDecision,
    ControllerOutcome,
    GovernanceController,
    GovernanceGraph,
    GovernanceLog,
    GovernanceOracle,
    OracleCase,
    OracleObservation,
)


FIXTURES_DIR = Path(__file__).parent / "fixtures"
COURNOT_MANIFEST = FIXTURES_DIR / "cournot_market.yaml"


# ---------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------


def _make_observation(
    *,
    manifest_semantic_sha256: str = "fake_digest",
) -> OracleObservation:
    return OracleObservation(
        snapshot_at=datetime.now(UTC),
        state_hash="abc",
        signal_evaluations={"S3_high_hhi": {"value": 0.6, "fired": True}},
        pending_cases=(
            OracleCase(
                case_id="c1",
                rule_id="P2_independent_decision",
                kind="probable_violation",
                actor_entity_id="firm_1",
                triggered_by_signals=("S3_high_hhi",),
                evidence={"hhi_excess": 0.6, "cv_excess": 0.0},
                severity_tier=3,
                observed_at=datetime.now(UTC),
                manifest_semantic_sha256=manifest_semantic_sha256,
            ),
        ),
        enabled_transitions=("R:active->warning",),
        manifest_semantic_sha256=manifest_semantic_sha256,
    )


def _make_decision(
    *,
    outcome: ControllerOutcome = ControllerOutcome.SANCTION,
    sanction_id: str | None = "fine_tier1",
    restorative_path_id: str | None = None,
    manifest_semantic_sha256: str = "fake_digest",
) -> ControllerDecision:
    return ControllerDecision(
        decision_id="d1",
        decision=outcome,
        edge_key="R:active->warning",
        rule_id="R",
        from_state="active",
        to_state="warning",
        triggered_by="probable_violation",
        sanction_id=sanction_id,
        restorative_path_id=restorative_path_id,
        case_id="c1",
        actor_entity_id="firm_1",
        effective_round=1,
        cooldown_until_round=2,
        rationale="test",
        manifest_semantic_sha256=manifest_semantic_sha256,
    )


# ---------------------------------------------------------------------
# Construction
# ---------------------------------------------------------------------


class TestGovernanceLogConstruction:
    def test_requires_signing_key_id(self) -> None:
        with pytest.raises(ValueError, match="signing_key_id"):
            GovernanceLog(signing_key_id="")

    def test_default_constructor_generates_keypair(self) -> None:
        log = GovernanceLog(signing_key_id="default-test")
        assert log.signing_key_id == "default-test"
        assert isinstance(log.public_key, bytes)
        assert len(log.public_key) > 0

    def test_explicit_keypair_must_match_key_id(self) -> None:
        from tex.events._ecdsa_provider import default_signature_provider

        provider = default_signature_provider()
        keypair = provider.generate_keypair("specific-id")
        with pytest.raises(ValueError, match="does not match"):
            GovernanceLog(
                signing_key_id="different-id",
                signing_keypair=keypair,
                signing_provider=provider,
            )

    def test_explicit_keypair_round_trips(self) -> None:
        from tex.events._ecdsa_provider import default_signature_provider

        provider = default_signature_provider()
        keypair = provider.generate_keypair("explicit")
        log = GovernanceLog(
            signing_key_id="explicit",
            signing_keypair=keypair,
            signing_provider=provider,
        )
        assert log.signing_key_id == "explicit"
        assert log.public_key == keypair.public_key


# ---------------------------------------------------------------------
# Independent signing key — the acceptance criterion
# ---------------------------------------------------------------------


class TestIndependentSigningKey:
    def test_two_logs_have_different_public_keys(self) -> None:
        """
        Each GovernanceLog generates its own keypair. Two logs with
        the same key_id but constructed at different times must NOT
        share private material.
        """
        log_a = GovernanceLog(signing_key_id="institutional")
        log_b = GovernanceLog(signing_key_id="institutional")
        assert log_a.public_key != log_b.public_key

    def test_governance_log_key_distinct_from_main_ledger(self) -> None:
        """
        The institutional log must be distinct from any other
        InMemoryLedger the application also constructs.
        """
        from tex.events._ecdsa_provider import default_signature_provider
        from tex.events.crypto_provenance import CryptoProvenance
        from tex.events.ledger import InMemoryLedger

        provider = default_signature_provider()
        main_keypair = provider.generate_keypair("main-events-ledger")
        main_ledger = InMemoryLedger(
            verifying_public_key=main_keypair.public_key,
            signing_provider=provider,
        )
        gov_log = GovernanceLog(signing_key_id="institutional")
        # Different key bytes prove independence.
        assert gov_log.public_key != main_keypair.public_key
        # And the wrong key cannot verify governance log entries
        # (we'll exercise this in the verification test).
        del main_ledger  # unused; kept for the demonstrative point


# ---------------------------------------------------------------------
# record_observation / record_decision
# ---------------------------------------------------------------------


class TestRecording:
    def test_record_observation_returns_event_id(self) -> None:
        log = GovernanceLog(signing_key_id="rec-obs")
        event_id = log.record_observation(
            oracle_observation=_make_observation()
        )
        assert isinstance(event_id, str)
        assert event_id.startswith("evt_")
        assert len(log) == 1

    def test_record_decision_returns_event_id(self) -> None:
        log = GovernanceLog(signing_key_id="rec-dec")
        event_id = log.record_decision(
            controller_decision=_make_decision()
        )
        assert isinstance(event_id, str)
        # SANCTION outcome appends two records (primary + paired
        # sanction_applied), but record_decision returns the primary id.
        assert len(log) == 2

    def test_record_decision_pairs_sanction_record_for_sanction_outcome(
        self,
    ) -> None:
        log = GovernanceLog(signing_key_id="paired-sanction")
        log.record_decision(
            controller_decision=_make_decision(
                outcome=ControllerOutcome.SANCTION,
                sanction_id="fine_tier1",
            )
        )
        records = log.all_records()
        assert len(records) == 2
        kinds = {r.kind for r in records}
        assert "governance_graph_transition" in kinds
        assert "sanction_applied" in kinds

    def test_record_decision_pairs_restoration_record_for_remediate(
        self,
    ) -> None:
        log = GovernanceLog(signing_key_id="paired-remediate")
        log.record_decision(
            controller_decision=_make_decision(
                outcome=ControllerOutcome.REMEDIATE,
                sanction_id=None,
                restorative_path_id="warning_expiry",
            )
        )
        records = log.all_records()
        assert len(records) == 2
        kinds = {r.kind for r in records}
        assert "governance_graph_transition" in kinds
        assert "restorative_path_triggered" in kinds

    def test_record_decision_does_not_pair_for_allow(self) -> None:
        log = GovernanceLog(signing_key_id="no-pair-allow")
        log.record_decision(
            controller_decision=_make_decision(
                outcome=ControllerOutcome.ALLOW,
                sanction_id=None,
            )
        )
        assert len(log) == 1

    def test_record_decision_does_not_pair_for_blocked(self) -> None:
        log = GovernanceLog(signing_key_id="no-pair-blocked")
        log.record_decision(
            controller_decision=_make_decision(
                outcome=ControllerOutcome.BLOCKED,
                sanction_id=None,
            )
        )
        assert len(log) == 1

    def test_record_observation_accepts_dict(self) -> None:
        """Back-compat: dicts work too (original scaffold signature)."""
        log = GovernanceLog(signing_key_id="dict-input")
        event_id = log.record_observation(
            oracle_observation={
                "actor_entity_id": "firm_1",
                "triggered_signals": ["S3_high_hhi"],
                "manifest_semantic_sha256": "deadbeef",
            }
        )
        assert event_id.startswith("evt_")
        assert len(log) == 1

    def test_record_decision_accepts_dict(self) -> None:
        log = GovernanceLog(signing_key_id="dict-decision")
        event_id = log.record_decision(
            controller_decision={
                "decision_id": "d1",
                "decision": "ALLOW",
                "from_state": "active",
                "to_state": "active",
                "triggered_by": "clean_round",
                "edge_key": "R:active->active",
                "rule_id": "R",
                "actor_entity_id": "firm_1",
                "effective_round": 1,
                "manifest_semantic_sha256": "deadbeef",
            }
        )
        assert event_id.startswith("evt_")

    def test_record_rejects_unsupported_payload_type(self) -> None:
        log = GovernanceLog(signing_key_id="bad-payload")
        with pytest.raises(TypeError, match="must be pydantic model or dict"):
            log.record_observation(oracle_observation=42)

    def test_record_quantises_floats(self) -> None:
        """
        Floats are quantised to milli-units to satisfy the canonical
        JSON contract (no IEEE-754 in the hashed payload).
        """
        log = GovernanceLog(signing_key_id="float-quantise")
        # The OracleCase model carries floats in evidence.
        log.record_observation(oracle_observation=_make_observation())
        # If quantisation failed, the canonicaliser would have raised.
        assert len(log) == 1


# ---------------------------------------------------------------------
# Chain integrity
# ---------------------------------------------------------------------


class TestChainIntegrity:
    def test_empty_log_verifies(self) -> None:
        log = GovernanceLog(signing_key_id="empty")
        assert log.verify_chain() is True

    def test_full_chain_verifies_after_appends(self) -> None:
        log = GovernanceLog(signing_key_id="chain-verify")
        log.record_observation(oracle_observation=_make_observation())
        log.record_decision(controller_decision=_make_decision())
        log.record_observation(oracle_observation=_make_observation())
        log.record_decision(
            controller_decision=_make_decision(
                outcome=ControllerOutcome.REMEDIATE,
                sanction_id=None,
                restorative_path_id="warning_expiry",
            )
        )
        # 1 obs + 2 (sanction pair) + 1 obs + 2 (remediate pair) = 6
        assert len(log) == 6
        assert log.verify_chain() is True

    def test_partial_range_verification(self) -> None:
        log = GovernanceLog(signing_key_id="partial-range")
        for _ in range(3):
            log.record_observation(oracle_observation=_make_observation())
        assert log.verify_chain(from_sequence=1, to_sequence=2) is True


# ---------------------------------------------------------------------
# Public-key verification (offline auditor flow)
# ---------------------------------------------------------------------


class TestExternalVerification:
    def test_correct_public_key_verifies_records(self) -> None:
        import base64

        from tex.events._ecdsa_provider import default_signature_provider

        log = GovernanceLog(signing_key_id="ext-verify")
        log.record_observation(oracle_observation=_make_observation())
        records = log.all_records()
        provider = default_signature_provider()
        # The auditor recomputes record_hash from the event content
        # (already done — it's stored on the Event) and verifies the
        # base64-decoded signature against the institutional public key.
        record = records[0]
        signature = base64.b64decode(record.pq_signature_b64)
        ok = provider.verify(
            record.record_hash.encode("utf-8"),
            signature,
            log.public_key,
        )
        assert ok is True

    def test_wrong_public_key_fails_verification(self) -> None:
        import base64

        from tex.events._ecdsa_provider import default_signature_provider

        log = GovernanceLog(signing_key_id="ext-wrong")
        log.record_observation(oracle_observation=_make_observation())
        records = log.all_records()
        provider = default_signature_provider()
        # Generate a totally unrelated keypair.
        wrong = provider.generate_keypair("wrong")
        signature = base64.b64decode(records[0].pq_signature_b64)
        ok = provider.verify(
            records[0].record_hash.encode("utf-8"),
            signature,
            wrong.public_key,
        )
        assert ok is False


# ---------------------------------------------------------------------
# End-to-end with the Cournot manifest
# ---------------------------------------------------------------------


class TestEndToEnd:
    def test_full_flow_through_controller(self) -> None:
        """Oracle observation -> Controller decision -> log records."""
        g = GovernanceGraph.from_yaml(COURNOT_MANIFEST)
        oracle = GovernanceOracle(graph=g, signals=())
        log = GovernanceLog(signing_key_id="e2e")
        controller = GovernanceController(oracle=oracle, ledger=log)

        # Three escalation steps: active -> warning -> fined -> suspended
        controller.enforce(
            proposed_event_kind="probable_violation",
            actor_entity_id="firm_1",
            current_round=1,
        )
        controller.enforce(
            proposed_event_kind="probable_violation",
            actor_entity_id="firm_1",
            current_round=2,
        )
        controller.enforce(
            proposed_event_kind="probable_violation",
            actor_entity_id="firm_1",
            current_round=10,
        )

        # 3 sanctions, each appends 2 records.
        assert len(log) == 6
        assert log.verify_chain() is True
        # Every record carries the manifest digest in its payload.
        for r in log.all_records():
            payload = r.payload
            # Some are primary decision records (full payload), others
            # are paired sanction_applied records (compact payload). Both
            # must include manifest_semantic_sha256.
            assert payload.get("manifest_semantic_sha256") == (
                g.manifest_semantic_sha256
            )
