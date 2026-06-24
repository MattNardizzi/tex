"""
P13/P5 SIGNED-IDENTITY plane tests (``sensors.identity_idp.IdentityIdpSensor``).

The directory / IdP plane is the EASY, calibration-anchor vantage: it sees the
signed/registered minority a connected directory already knows. These tests
prove the two load-bearing contracts:

1. A planted directory (a ``FixtureGraphTransport`` over ``servicePrincipals`` +
   their ``oauth2PermissionGrants``) emits CORRECT ``Incidence`` records — the
   right ``FootprintField`` keys at the right ``EdgeGrade`` (so ``fuse.py`` can
   link on the strong ``oidc_sub`` and split on the bridging ``oauth_grant_id``),
   the right ``Admissibility`` (``PROVEN`` for a bound SVID, ``PLATFORM_ATTESTED``
   for a directory-only SP), and the signed-cohort catchability.
2. The sensor degrades to EMPTY (yields nothing, never raises) when no directory
   is connected (``transport=None``) or the transport errors — the common case.

Plus the flag-gating / default-safe contract at the registry boundary: the plane
is OFF unless ``TEX_SIEVE_P13_SIGNED`` is set, and even when enabled with no IdP
creds it builds an inert sensor that senses nothing.

Run:
    cd /Users/matthewnardizzi/dev/tex-discovery && \
      PYTHONPATH=/Users/matthewnardizzi/dev/tex-discovery/src \
      /Users/matthewnardizzi/dev/tex/.venv/bin/python -m pytest \
      tests/test_discovery_plane_identity.py -q
"""

from __future__ import annotations

from tex.discovery.engine.fuse import _grade_for_key, resolve
from tex.discovery.engine.models import (
    Admissibility,
    EdgeGrade,
    FootprintField,
    Incidence,
    PlaneId,
)
from tex.discovery.engine.sensors.base import SenseContext
from tex.discovery.engine.sensors.identity_idp import (
    SIGNED_ID_CATCHABILITY,
    IdentityIdpSensor,
)
from tex.discovery.graph_transport import FixtureGraphTransport


# ---------------------------------------------------------------------------
# Fixture: a tiny planted directory (Graph-shaped service principals + grants).
# ---------------------------------------------------------------------------


def _planted_directory() -> FixtureGraphTransport:
    """Two signed agents: one directory-only SP, one with a bound SVID.

    - ``AssayPilot`` — a plain registered SP. Its OAuth grant lives in the
      ``oauth2PermissionGrants`` sub-collection (so the sensor must fetch it).
    - ``DeployBot``  — an SP with a runtime SPIFFE/SVID bound (PROVEN identity)
      and an inline grant.
    """
    return FixtureGraphTransport(
        pages={
            "servicePrincipals": [
                {
                    "id": "sp-obj-assay-001",
                    "appId": "app-assay-aaaa-bbbb",
                    "displayName": "AssayPilot",
                    "servicePrincipalType": "Application",
                    "accountEnabled": True,
                },
                {
                    "id": "sp-obj-deploy-002",
                    "appId": "app-deploy-cccc-dddd",
                    "displayName": "DeployBot",
                    "spiffeId": "spiffe://corp/ns/prod/sa/deploybot",
                    "oauth_grant_id": "grant-deploy-inline-9",
                    "accountEnabled": True,
                },
            ],
            "servicePrincipals/sp-obj-assay-001/oauth2PermissionGrants": [
                {"id": "grant-assay-7777", "scope": "User.Read"},
            ],
        }
    )


def _sense(transport) -> list[Incidence]:
    sensor = IdentityIdpSensor(transport=transport, evidence_label="entra")
    return list(sensor.sense(SenseContext()))


def _by_oidc(incidences: list[Incidence], oidc_sub: str) -> Incidence:
    for inc in incidences:
        if inc.footprint.key(FootprintField.OIDC_SUB.value) == oidc_sub:
            return inc
    raise AssertionError(f"no incidence with oidc_sub={oidc_sub!r}")


# ---------------------------------------------------------------------------
# (1) A planted directory emits correct incidences.
# ---------------------------------------------------------------------------


def test_planted_directory_emits_incidences_with_correct_footprints() -> None:
    incidences = _sense(_planted_directory())
    assert len(incidences) == 2

    # All on the SIGNED_ID plane, all carrying the signed-cohort catchability.
    for inc in incidences:
        assert inc.plane_id is PlaneId.SIGNED_ID
        assert inc.footprint.plane_id is PlaneId.SIGNED_ID
        assert inc.catchability == SIGNED_ID_CATCHABILITY

    # The directory-only SP: PLATFORM_ATTESTED, strong oidc_sub, bridging
    # sp_object_id + oauth_grant_id (fetched from the sub-collection).
    assay = _by_oidc(incidences, "app-assay-aaaa-bbbb")
    assert assay.admissibility is Admissibility.PLATFORM_ATTESTED
    assert assay.footprint.key(FootprintField.SP_OBJECT_ID.value) == "sp-obj-assay-001"
    assert assay.footprint.key(FootprintField.OAUTH_GRANT_ID.value) == "grant-assay-7777"
    assert assay.footprint.key(FootprintField.SPIFFE_ID.value) is None
    assert assay.footprint.attr("app_display_name") == "AssayPilot"
    assert "entra:servicePrincipals/" in assay.raw_evidence_ref


def test_bound_svid_is_proven_runtime_identity() -> None:
    incidences = _sense(_planted_directory())
    deploy = _by_oidc(incidences, "app-deploy-cccc-dddd")
    # A bound SVID is a verified handshake → PROVEN (strongest grade).
    assert deploy.admissibility is Admissibility.PROVEN
    assert (
        deploy.footprint.key(FootprintField.SPIFFE_ID.value)
        == "spiffe://corp/ns/prod/sa/deploybot"
    )
    # The inline grant id is used without a sub-collection fetch.
    assert (
        deploy.footprint.key(FootprintField.OAUTH_GRANT_ID.value)
        == "grant-deploy-inline-9"
    )


def test_footprint_keys_carry_the_grades_fuse_links_and_splits_on() -> None:
    """The strong/bridging grades fuse.py needs are present by schema."""
    # oidc_sub + spiffe_id MUST be identity-grade (close transitively → link).
    assert _grade_for_key(FootprintField.OIDC_SUB.value) is EdgeGrade.IDENTITY
    assert _grade_for_key(FootprintField.SPIFFE_ID.value) is EdgeGrade.IDENTITY
    # sp_object_id + oauth_grant_id MUST be bridging (the N1 split source).
    assert _grade_for_key(FootprintField.SP_OBJECT_ID.value) is EdgeGrade.BRIDGING
    assert _grade_for_key(FootprintField.OAUTH_GRANT_ID.value) is EdgeGrade.BRIDGING


def test_signed_identity_fuses_with_a_cross_plane_sighting_on_oidc_sub() -> None:
    """End-to-end: a directory SP + an external sighting sharing the signed
    ``oidc_sub`` fuse to exactly ONE entity (the calibration anchor doing its
    job — linking a signed identity to its other-plane footprint)."""
    directory_incs = _sense(_planted_directory())
    assay = _by_oidc(directory_incs, "app-assay-aaaa-bbbb")

    # A second plane (e.g. a network-egress sighting) that also carries the same
    # signed oidc_sub — the strong cross-plane join key.
    from tex.discovery.engine.models import FootprintVector

    other = Incidence(
        plane_id=PlaneId.NETWORK_EGRESS,
        footprint=FootprintVector.of(
            plane_id=PlaneId.NETWORK_EGRESS,
            keys={FootprintField.OIDC_SUB.value: "app-assay-aaaa-bbbb"},
        ),
        catchability=1.0,
        admissibility=Admissibility.OBSERVED,
        raw_evidence_ref="egress:flow/42",
    )

    entities = resolve([assay, other])
    # The signed identity and its other-plane sighting fuse to ONE entity seen
    # on BOTH capture occasions.
    assert len(entities) == 1
    (entity,) = entities
    assert entity.planes_seen >= {PlaneId.SIGNED_ID, PlaneId.NETWORK_EGRESS}


# ---------------------------------------------------------------------------
# (2) Degrade to EMPTY — never raise — when no directory is connected.
# ---------------------------------------------------------------------------


def test_no_transport_degrades_to_empty() -> None:
    sensor = IdentityIdpSensor(transport=None)
    assert list(sensor.sense(SenseContext())) == []


def test_empty_directory_degrades_to_empty() -> None:
    sensor = IdentityIdpSensor(transport=FixtureGraphTransport(pages={}))
    assert list(sensor.sense(SenseContext())) == []


def test_raising_transport_degrades_to_empty_never_raises() -> None:
    class _BoomTransport:
        def get_paginated(self, path, params=None):  # noqa: ANN001, ARG002
            raise RuntimeError("directory unreachable")

    sensor = IdentityIdpSensor(transport=_BoomTransport())
    # Must NOT propagate — degrade to empty.
    assert list(sensor.sense(SenseContext())) == []


def test_grant_subcollection_error_keeps_the_sp_sighting() -> None:
    """A failure fetching the OAuth-grant sub-collection must NOT drop the
    identity — the SP is still a real signed sighting (without a grant id)."""

    class _PartialTransport:
        def get_paginated(self, path, params=None):  # noqa: ANN001, ARG002
            if path == "servicePrincipals":
                return iter(
                    [
                        {
                            "id": "sp-x",
                            "appId": "app-x",
                            "displayName": "X",
                        }
                    ]
                )
            raise RuntimeError("grants endpoint throttled")

    sensor = IdentityIdpSensor(transport=_PartialTransport())
    incidences = list(sensor.sense(SenseContext()))
    assert len(incidences) == 1
    inc = incidences[0]
    assert inc.footprint.key(FootprintField.OIDC_SUB.value) == "app-x"
    # No grant id (the fetch failed) — but the SP sighting survived.
    assert inc.footprint.key(FootprintField.OAUTH_GRANT_ID.value) is None


def test_object_without_any_usable_key_is_skipped() -> None:
    sensor = IdentityIdpSensor(
        transport=FixtureGraphTransport(
            pages={"servicePrincipals": [{"displayName": "nameless"}, {"id": "ok-1"}]}
        )
    )
    incidences = list(sensor.sense(SenseContext()))
    # The first object has no oidc_sub/spiffe/sp_object_id → skipped; the second
    # has an sp_object_id → kept.
    assert len(incidences) == 1
    assert incidences[0].footprint.key(FootprintField.SP_OBJECT_ID.value) == "ok-1"


# ---------------------------------------------------------------------------
# Flag-gating / default-safe at the registry boundary.
# ---------------------------------------------------------------------------


def test_registry_default_safe_off_without_flag() -> None:
    from tex.discovery.engine.sensors.registry import build_active_sensors

    # No flags at all → no sensors (a merge-to-main / prod deploy stays inert).
    assert build_active_sensors({}) == []


def test_registry_flag_on_no_creds_builds_inert_sensor() -> None:
    from tex.discovery.engine.sensors.registry import build_active_sensors

    sensors = build_active_sensors({"TEX_SIEVE_P13_SIGNED": "1"})
    assert len(sensors) == 1
    sensor = sensors[0]
    assert sensor.plane_id is PlaneId.SIGNED_ID
    # Flag-enabled but no directory creds → inert, senses nothing.
    assert list(sensor.sense(SenseContext())) == []
