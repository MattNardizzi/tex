"""
Phase 1 gate (broker): the four-state connect machine, honestly multi-step.

  * Entra consent is one-click; Okta consent is multi-step (and the
    appGrants.read step is flagged Super-Admin + optional) — the button is one
    *entry point*, not one *click*.
  * REQUESTED -> CONSENTED -> PROBED -> SEALED, enforced; out-of-order fails.
  * A full Okta connect flow ends with a GRANT_SEALED receipt that verifies
    offline.
  * Withholding okta.appGrants.read yields a DEGRADED (partial) grant, not a
    crash or a silent drop.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from tex.discovery.conduit.broker import (
    ConnectBroker,
    ConnectState,
    InvalidStateTransition,
)
from tex.discovery.conduit.providers.base import ConsentCallback
from tex.discovery.conduit.providers.entra import EntraConnectStrategy
from tex.discovery.conduit.providers.okta import OKTA_READ_SCOPES, OktaConnectStrategy
from tex.discovery.conduit.seal import ConduitEventKind, ConduitProvenanceChain
from tex.discovery.graph_transport import FixtureGraphTransport
from tex.domain.discovery import DiscoverySource

_FIXTURES = Path(__file__).parent / "fixtures"


def _okta_fixture_factory(grant):
    apps = json.loads((_FIXTURES / "okta_apps.json").read_text())
    grants = json.loads((_FIXTURES / "okta_grants.json").read_text())
    pages: dict[str, list] = {"apps": apps}
    for app_id, rows in grants.items():
        pages[f"apps/{app_id}/grants"] = rows
    return FixtureGraphTransport(pages)


def _broker():
    chain = ConduitProvenanceChain(origin="tex.conduit/test-broker")
    broker = ConnectBroker(
        strategies=[
            EntraConnectStrategy(),
            OktaConnectStrategy(transport_factory=_okta_fixture_factory),
        ],
        chain=chain,
    )
    return broker, chain


def test_entra_consent_is_one_click_okta_is_not():
    broker, _ = _broker()
    entra = broker.request(DiscoverySource.MICROSOFT_GRAPH, "acme", nonce="n1")
    assert entra.is_one_click is True

    okta = broker.request(DiscoverySource.OKTA, "acme", nonce="n2")
    assert okta.is_one_click is False
    assert len(okta.steps) == 3
    appgrants_step = next(s for s in okta.steps if s.step_id == "grant_app_grants_read")
    assert appgrants_step.needs_super_admin is True
    assert appgrants_step.optional is True


def test_full_okta_connect_flow_seals_verifiable_receipt():
    broker, chain = _broker()
    challenge = broker.request(DiscoverySource.OKTA, "acme", nonce="full")
    cid = challenge.connection_id

    grant = broker.consent(
        ConsentCallback(
            connection_id=cid,
            consent_artifact_id="0oaSERVICEAPP",
            granted_scopes=OKTA_READ_SCOPES,  # everything granted
            credential_ref="vault://tex/okta/acme",
            consented_by="admin@acme.example",
        )
    )
    assert grant.degraded is False
    assert broker.connection(cid).state is ConnectState.CONSENTED

    conn = broker.probe(cid)
    assert conn.state is ConnectState.PROBED
    assert conn.transport is not None  # transport_factory resolved

    receipt = broker.seal(cid)
    assert broker.connection(cid).state is ConnectState.SEALED
    assert receipt.kind is ConduitEventKind.GRANT_SEALED
    assert receipt.verify(pinned_log_public_key_b64=chain.public_key_b64()).ok


def test_withheld_appgrants_yields_degraded_grant():
    broker, _ = _broker()
    challenge = broker.request(DiscoverySource.OKTA, "acme", nonce="partial")
    granted = tuple(s for s in OKTA_READ_SCOPES if s != "okta.appgrants.read")
    grant = broker.consent(
        ConsentCallback(
            connection_id=challenge.connection_id,
            consent_artifact_id="0oaSERVICEAPP",
            granted_scopes=granted,
            credential_ref="vault://tex/okta/acme",
        )
    )
    assert grant.degraded is True
    assert "okta.appgrants.read" in grant.missing_scopes


def test_out_of_order_transitions_fail():
    broker, _ = _broker()
    challenge = broker.request(DiscoverySource.OKTA, "acme", nonce="oops")
    # Cannot seal before probe (still REQUESTED).
    with pytest.raises(InvalidStateTransition):
        broker.seal(challenge.connection_id)
    # Cannot probe before consent.
    with pytest.raises(InvalidStateTransition):
        broker.probe(challenge.connection_id)


def test_unknown_connection_and_provider_fail():
    broker, _ = _broker()
    from tex.discovery.conduit.broker import ConnectBrokerError

    with pytest.raises(ConnectBrokerError):
        broker.connection("does::not-exist")
    with pytest.raises(ConnectBrokerError):
        broker.request(DiscoverySource.GENERIC, "acme", nonce="x")
