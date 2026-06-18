"""
Phase 5 gate: opt-in provenance tiers, with a working floor when they're off.

  * Tiers toggle purely by configuration.
  * The Ed25519 + RFC-3161 FLOOR seals and verifies regardless of tiers — so a
    deployment with every tier off still gets a valid, offline-verifiable
    receipt.
  * Honesty: witness cosigning is requested-but-not-active this wave
    (federated=False); ML-DSA is auto-on only where the backend is present.
"""

from __future__ import annotations

from datetime import UTC, datetime

from tex.discovery.conduit.grant import DirectoryGrant
from tex.discovery.conduit.seal import ConduitProvenanceChain, seal_grant
from tex.discovery.conduit.tiers import (
    FLOOR_ANCHOR,
    FLOOR_SIGNING,
    ProvenanceTier,
    ProvenanceTierConfig,
    ml_dsa_backend_available,
)
from tex.domain.discovery import DiscoverySource


def test_all_tiers_off_floor_still_seals_and_verifies():
    cfg = ProvenanceTierConfig.from_env(
        {
            "TEX_CONDUIT_ML_DSA": "off",
            "TEX_CONDUIT_WITNESS_COSIGN": "off",
            "TEX_CONDUIT_OPENTIMESTAMPS": "off",
        }
    )
    assert cfg.active_tiers() == ()
    assert cfg.floor_signing == FLOOR_SIGNING
    assert cfg.floor_anchor == FLOOR_ANCHOR

    # The floor works independent of any tier: seal + verify offline.
    chain = ConduitProvenanceChain(origin="tex.conduit/test-floor")
    grant = DirectoryGrant(
        provider=DiscoverySource.OKTA,
        tenant_id="acme",
        requested_scopes=["okta.apps.read"],
        granted_scopes=["okta.apps.read"],
        consent_artifact_id="0oa1",
        granted_at=datetime.now(UTC),
        credential_ref="vault://tex/okta/acme",
    )
    receipt = seal_grant(chain, grant)
    assert receipt.verify(pinned_log_public_key_b64=chain.public_key_b64()).ok


def test_ml_dsa_auto_tracks_backend_availability():
    expected = ml_dsa_backend_available()
    cfg = ProvenanceTierConfig.from_env({"TEX_CONDUIT_ML_DSA": "auto"})
    assert cfg.ml_dsa.available is expected
    assert cfg.ml_dsa.active is expected  # auto -> active exactly where available

    # Explicit off never activates, even if the backend exists.
    off = ProvenanceTierConfig.from_env({"TEX_CONDUIT_ML_DSA": "off"})
    assert off.ml_dsa.active is False


def test_witness_is_requested_but_not_active_this_wave():
    cfg = ProvenanceTierConfig.from_env({"TEX_CONDUIT_WITNESS_COSIGN": "on"})
    assert cfg.witness.requested is True
    assert cfg.witness.available is False  # federated=False until a real witness runs
    assert cfg.witness.active is False
    assert "federated=False" in cfg.witness.detail
    assert ProvenanceTier.WITNESS_COSIGN not in cfg.active_tiers()


def test_opentimestamps_needs_a_calendar():
    off = ProvenanceTierConfig.from_env({"TEX_CONDUIT_OPENTIMESTAMPS": "on"})
    assert off.opentimestamps.active is False  # no calendar configured

    on = ProvenanceTierConfig.from_env(
        {
            "TEX_CONDUIT_OPENTIMESTAMPS": "on",
            "TEX_CONDUIT_OTS_CALENDAR": "https://alice.btc.calendar.opentimestamps.org",
        }
    )
    assert on.opentimestamps.active is True
    assert ProvenanceTier.OPENTIMESTAMPS_ANCHOR in on.active_tiers()


def test_report_carries_compliance_mapping():
    cfg = ProvenanceTierConfig.from_env({"TEX_CONDUIT_ML_DSA": "off"})
    report = cfg.report()
    assert report["floor"]["always_active"] is True
    assert any("AU-10" in c for c in report["floor"]["compliance"])
    ml = report["tiers"]["ml_dsa_seal"]
    assert any("FIPS 204" in c for c in ml["compliance"])
    wit = report["tiers"]["witness_cosign"]
    assert any("AU-9" in c for c in wit["compliance"])
