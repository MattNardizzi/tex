"""
Tests for the new compliance jurisdictions added in the May 2026
frontier upgrade:

- NY AI Advertising Disclosure (§1700-A, effective 1 June 2026)
- Colorado AI Act (SB 24-205 as amended, effective 30 June 2026)
- EU AI Act Article 17 QMS (effective 2 August 2026)
- EU AI Act Article 26 Deployer Obligations (effective 2 August 2026)
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from tex.compliance.eu_ai_act.article_17 import (
    Article17QmsPayload,
    CorrectiveAction,
    PostMarketMonitoringWindow,
    emit_article_17_evidence,
)
from tex.compliance.eu_ai_act.article_26 import (
    Article26DeployerPayload,
    HumanOversightAssignee,
    emit_article_26_evidence,
)
from tex.compliance.state.colorado_ai_act import (
    ColoradoAiActPayload,
    emit_co_ai_evidence,
)
from tex.compliance.state.new_york_ai_disclosure import (
    NyAiDisclosurePayload,
    emit_ny_disclosure,
)


# --- NY §1700-A -------------------------------------------------------------


def _ny_kwargs(**overrides):
    base = dict(
        c2pa_manifest_id="urn:uuid:abc",
        content_sha256="a" * 64,
        synthetic_performer_used=True,
        disclosure_text="This ad features a synthetic performer.",
        placement="persistent_overlay",
        advertiser_legal_entity="Acme LLC",
        publication_window_start=datetime(2026, 6, 1, tzinfo=timezone.utc),
        publication_window_end=datetime(2026, 6, 30, tzinfo=timezone.utc),
    )
    base.update(overrides)
    return base


def test_ny_emits_payload_with_statute_version():
    p = emit_ny_disclosure(**_ny_kwargs())
    assert isinstance(p, NyAiDisclosurePayload)
    assert p.statute_version == "GBL_1700-A_2026-06"
    assert p.placement == "persistent_overlay"


def test_ny_rejects_empty_manifest_id():
    with pytest.raises(ValueError, match="c2pa_manifest_id"):
        emit_ny_disclosure(**_ny_kwargs(c2pa_manifest_id=""))


def test_ny_rejects_short_hash():
    with pytest.raises(ValueError, match="content_sha256"):
        emit_ny_disclosure(**_ny_kwargs(content_sha256="abc"))


def test_ny_requires_disclosure_text_when_synthetic():
    with pytest.raises(ValueError, match="disclosure_text"):
        emit_ny_disclosure(
            **_ny_kwargs(synthetic_performer_used=True, disclosure_text="")
        )


def test_ny_allows_negative_attestation():
    """When synthetic_performer_used=False, the record is a positive
    attestation that §1700-A does not apply."""
    p = emit_ny_disclosure(
        **_ny_kwargs(synthetic_performer_used=False, disclosure_text="")
    )
    assert p.synthetic_performer_used is False


def test_ny_rejects_inverted_window():
    with pytest.raises(ValueError, match="publication_window_end"):
        emit_ny_disclosure(
            **_ny_kwargs(
                publication_window_start=datetime(2026, 7, 1, tzinfo=timezone.utc),
                publication_window_end=datetime(2026, 6, 1, tzinfo=timezone.utc),
            )
        )


# --- Colorado AI Act --------------------------------------------------------


def _co_kwargs(**overrides):
    base = dict(
        deployer_legal_entity="Acme",
        system_purpose="employment",
        system_version="1.0",
        algorithmic_discrimination_risk_assessment=(
            "Reviewed fairness across protected classes; no disparate impact."
        ),
        human_oversight_summary="Two reviewers + escalation to head of HR.",
        individual_consumer_notice_provided=True,
        impact_assessment_date=datetime(2026, 6, 15, tzinfo=timezone.utc),
    )
    base.update(overrides)
    return base


def test_colorado_emits_payload_with_statute_version():
    p = emit_co_ai_evidence(**_co_kwargs())
    assert isinstance(p, ColoradoAiActPayload)
    assert p.statute_version == "SB_24-205_as_amended_2026-06"
    assert p.system_purpose == "employment"


def test_colorado_requires_risk_assessment_narrative():
    with pytest.raises(ValueError, match="algorithmic_discrimination"):
        emit_co_ai_evidence(
            **_co_kwargs(algorithmic_discrimination_risk_assessment=" ")
        )


def test_colorado_requires_human_oversight_summary():
    with pytest.raises(ValueError, match="human_oversight_summary"):
        emit_co_ai_evidence(**_co_kwargs(human_oversight_summary=""))


def test_colorado_accepts_optional_c2pa_binding():
    p = emit_co_ai_evidence(**_co_kwargs(c2pa_manifest_id="urn:uuid:xyz"))
    assert p.c2pa_manifest_id == "urn:uuid:xyz"


# --- EU AI Act Article 17 ---------------------------------------------------


def _a17_kwargs(**overrides):
    base = dict(
        provider_legal_entity="Acme AI",
        high_risk_system_name="resume-screener",
        high_risk_system_version="2.1.0",
        qms_policy_url="https://acme.example/qms",
        post_market_monitoring=PostMarketMonitoringWindow(
            window_start=datetime(2026, 1, 1, tzinfo=timezone.utc),
            window_end=datetime(2026, 6, 30, tzinfo=timezone.utc),
            deployments_observed=10,
            serious_incidents_reported=0,
            near_misses_logged=1,
        ),
        corrective_actions=[],
        version_control_repository_url="https://github.com/acme/resume-screener",
    )
    base.update(overrides)
    return base


def test_a17_defaults_to_all_eleven_qms_components():
    p = emit_article_17_evidence(**_a17_kwargs())
    assert isinstance(p, Article17QmsPayload)
    # Article 17(1)(a)-(k) = 11 components.
    assert len(p.qms_components_implemented) == 11


def test_a17_rejects_unknown_component():
    with pytest.raises(ValueError, match="Unknown"):
        emit_article_17_evidence(
            **_a17_kwargs(qms_components_implemented=["not_a_real_component"])
        )


def test_a17_accepts_subset_of_components():
    p = emit_article_17_evidence(
        **_a17_kwargs(
            qms_components_implemented=[
                "risk_management_system",
                "post_market_monitoring_system",
            ]
        )
    )
    assert len(p.qms_components_implemented) == 2


def test_a17_carries_corrective_actions():
    action = CorrectiveAction(
        incident_id="inc-1",
        opened_at=datetime(2026, 2, 1, tzinfo=timezone.utc),
        closed_at=datetime(2026, 2, 10, tzinfo=timezone.utc),
        root_cause="false-positive on protected-class names",
        remediation="retrained on balanced dataset",
        bound_evidence_ids=("evt-1", "evt-2"),
    )
    p = emit_article_17_evidence(**_a17_kwargs(corrective_actions=[action]))
    assert len(p.corrective_actions) == 1
    assert p.corrective_actions[0].incident_id == "inc-1"


def test_a17_requires_qms_policy_url():
    with pytest.raises(ValueError, match="qms_policy_url"):
        emit_article_17_evidence(**_a17_kwargs(qms_policy_url=""))


# --- EU AI Act Article 26 ---------------------------------------------------


def _assignee(role: str = "HR Lead") -> HumanOversightAssignee:
    return HumanOversightAssignee(
        person_identifier=f"reviewer-{role.lower().replace(' ', '-')}",
        role=role,
        competence_summary="10y HR + AI training",
        training_completed_at=datetime(2026, 3, 1, tzinfo=timezone.utc),
    )


def _a26_kwargs(**overrides):
    base = dict(
        deployer_legal_entity="Hiring Corp",
        high_risk_system_name="resume-screener",
        high_risk_system_version="2.1.0",
        provider_legal_entity="Acme AI",
        instructions_for_use_url="https://acme.example/ifu",
        human_oversight_assignees=[_assignee()],
        input_data_relevance_attestation="Resumes only; no protected-class fields.",
        logs_retention_window=timedelta(days=365),
        affected_persons_notice_template_url="https://hiring.example/notice",
    )
    base.update(overrides)
    return base


def test_a26_emits_payload():
    p = emit_article_26_evidence(**_a26_kwargs())
    assert isinstance(p, Article26DeployerPayload)
    assert p.incident_reporting_max_delay_hours == 72
    assert p.statute_version == "AIA_Art_26_2026-08"


def test_a26_requires_at_least_one_oversight_assignee():
    with pytest.raises(ValueError, match="HumanOversightAssignee"):
        emit_article_26_evidence(**_a26_kwargs(human_oversight_assignees=[]))


def test_a26_enforces_six_month_minimum_retention():
    """§26(6) statutory minimum."""
    with pytest.raises(ValueError, match="6-month"):
        emit_article_26_evidence(
            **_a26_kwargs(logs_retention_window=timedelta(days=30))
        )


def test_a26_rejects_incident_sla_above_72_hours():
    with pytest.raises(ValueError, match="72-hour"):
        emit_article_26_evidence(
            **_a26_kwargs(incident_reporting_max_delay_hours=96)
        )


def test_a26_allows_stricter_internal_sla():
    p = emit_article_26_evidence(
        **_a26_kwargs(incident_reporting_max_delay_hours=24)
    )
    assert p.incident_reporting_max_delay_hours == 24


def test_a26_requires_input_data_relevance_attestation():
    with pytest.raises(ValueError, match="input_data_relevance"):
        emit_article_26_evidence(
            **_a26_kwargs(input_data_relevance_attestation=" ")
        )


def test_a26_carries_bound_evidence_ids():
    p = emit_article_26_evidence(
        **_a26_kwargs(bound_evidence_ids=("c2pa:1", "scitt:2"))
    )
    assert p.bound_evidence_ids == ("c2pa:1", "scitt:2")


# --- Cross-jurisdiction alignment -------------------------------------------


def test_all_four_modules_share_c2pa_binding_convention():
    """All four jurisdictions reference a C2PA manifest id as the
    cryptographic anchor for their disclosures. This is the value the
    GTM-A AI-SDR brand-safety pitch leans on."""
    ny = emit_ny_disclosure(**_ny_kwargs(c2pa_manifest_id="urn:uuid:1"))
    co = emit_co_ai_evidence(**_co_kwargs(c2pa_manifest_id="urn:uuid:2"))
    assert ny.c2pa_manifest_id == "urn:uuid:1"
    assert co.c2pa_manifest_id == "urn:uuid:2"
    # Article 17 and 26 reference via bound_evidence_ids (more flexible
    # for the multi-artifact case).
    a17 = emit_article_17_evidence(**_a17_kwargs())
    a26 = emit_article_26_evidence(**_a26_kwargs(bound_evidence_ids=("urn:uuid:3",)))
    assert a17.qms_policy_url.startswith("https://")
    assert "urn:uuid:3" in a26.bound_evidence_ids
