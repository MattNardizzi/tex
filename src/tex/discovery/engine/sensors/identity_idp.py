"""
P13 / P5 — the SIGNED-IDENTITY plane (``PlaneId.SIGNED_ID``).

The directory / IdP vantage: the cryptographically- or platform-attested agent
identities a connected directory already KNOWS about — Entra/Graph service
principals + their OAuth2 permission grants, the Okta service-app + client +
app-grant census, and (where present) a runtime SPIFFE/SVID workload identity.

This is the EASY case (RESEARCH_LOG §1, line 403: P13 catchability = 1.0 for the
signed subset *by construction* — the marked set). The architecture is emphatic
that this plane is the **marked-recapture CALIBRATION anchor, never the discovery
mechanism** (RESEARCH_LOG §P13). It must therefore stay lean and — critically —
it MUST NOT be the only plane that ever fires: a directory only sees the opt-in,
signed, registered minority. A gate-bypassing shadow that never registered an
app or SP is INVISIBLE here, which is exactly why the kernel/network/fs planes
exist. So this sensor reports honestly and degrades to EMPTY whenever no
directory is connected (the common case).

Signal SOURCE, not a new connector
----------------------------------
The sensor wraps the existing conduit providers' read seam — a
``GraphTransport`` (Microsoft Graph ``servicePrincipals`` +
``oauth2PermissionGrants``; Okta's ``/api/v1`` is the same shape behind the same
transport Protocol) — purely as a SIGNAL source. It does no consent dance and
holds no secret: a deployment hands it an already-built transport (resolved from
the sealed ``DirectoryGrant.credential_ref``); tests inject a
``FixtureGraphTransport``. With no transport it senses nothing.

Footprint it emits (the FootprintField vocabulary fuse.py links/splits on)
--------------------------------------------------------------------------
- ``oidc_sub``       — IDENTITY-grade. The signed OIDC subject / appId. A match
                       means "same agent" and MUST close transitively (fuse.py
                       ``_IDENTITY_KEYS``). This is the strong cross-plane anchor.
- ``spiffe_id``      — IDENTITY-grade. A runtime SVID workload identity, emitted
                       only when actually present, with admissibility=PROVEN.
- ``sp_object_id``   — BRIDGING-grade. The directory object id; a coarse link
                       (one SP can front several agents), never a merge alone.
- ``oauth_grant_id`` — BRIDGING-grade. One shared app credential / grant can
                       collapse k agents — the positive N1 shared-credential
                       SPLIT source (fuse.py ``_BRIDGING_KEYS``).
- ``app_display_name`` (attr) — descriptive label for receipts; not matched on.

Admissibility (models.Admissibility, strongest→weakest):
- ``PROVEN``            for an SVID/SPIFFE runtime identity (a verified handshake).
- ``PLATFORM_ATTESTED`` for a directory-attested SP / OAuth grant (the IdP
                        asserts it; trusted only as far as the platform).

Catchability is ASSERTED 1.0 for the signed subset by construction (the marked
cohort) — NOT a measured recall of the whole estate. The count-based slice
estimator carries-but-does-not-consume it; calibrating per-plane recall AGAINST
this marked set is the Phase-5 N2 target, not something this sensor claims.

HARD RULES honored:
- Degrades to EMPTY (yields nothing, never raises) when no transport is
  connected, the transport errors, or it returns no objects.
- FLAG-GATED OFF by default behind ``TEX_SIEVE_P13_SIGNED`` (registry); adding
  the sensor does not activate it — only the env flag does.
"""

from __future__ import annotations

import logging
from typing import Any, Iterable, Iterator, Mapping

from tex.discovery.engine.models import (
    Admissibility,
    FootprintField,
    FootprintVector,
    Incidence,
    PlaneId,
)
from tex.discovery.engine.sensors.base import SenseContext

_logger = logging.getLogger(__name__)

#: ASSERTED catchability of the signed cohort: 1.0 BY CONSTRUCTION — every member
#: of the marked (signed/registered) set is, definitionally, captured here. This
#: is NOT a claim about the whole estate's recall (the directory misses every
#: unregistered shadow); it is the marked-set property the Phase-5 calibrator
#: leans on. Carried-but-unused by the count-based slice estimator.
SIGNED_ID_CATCHABILITY = 1.0

#: The directory collection a Graph-shaped transport enumerates for agent
#: identities. Okta's app census is the same shape behind the same transport.
_SERVICE_PRINCIPALS_PATH = "servicePrincipals"

#: Per-SP sub-collection of consented OAuth2 permission grants. Formatted with
#: the SP object id; one grant can collapse k agents (the N1 bridging source).
_OAUTH_GRANTS_PATH = "servicePrincipals/{sp_id}/oauth2PermissionGrants"


class IdentityIdpSensor:
    """Emits one ``Incidence`` per signed/attested directory identity (P13/P5).

    Construct with an optional ``transport`` (any ``GraphTransport``-shaped
    object exposing ``get_paginated``) — the already-built read seam over a
    connected directory. With ``transport=None`` the sensor is inert and
    ``sense`` yields nothing (the common, no-directory-connected case).

    ``sense`` ignores ``SenseContext`` (the directory is a remote API, not a
    local path) and reads the transport. Any transport error degrades to fewer
    incidences, never an exception.
    """

    plane_id: PlaneId = PlaneId.SIGNED_ID

    def __init__(
        self,
        transport: Any | None = None,
        *,
        catchability: float = SIGNED_ID_CATCHABILITY,
        evidence_label: str = "directory",
    ) -> None:
        self._transport = transport
        self._catchability = catchability
        # A short opaque tag for raw_evidence_ref (e.g. "entra", "okta") so the
        # receipt names the source directory without leaking a secret.
        self._evidence_label = str(evidence_label or "directory")

    def sense(self, context: SenseContext) -> Iterable[Incidence]:  # noqa: ARG002
        """Enumerate signed directory identities into ``Incidence`` records.

        Degrades to an empty iterable when no transport is connected, the
        transport raises, or it returns no objects. NEVER raises.
        """
        return list(self._iter())

    # ------------------------------------------------------------------
    # internals
    # ------------------------------------------------------------------

    def _iter(self) -> Iterator[Incidence]:
        transport = self._transport
        if transport is None:
            return  # no directory connected — the common case, sense nothing.
        get_paginated = getattr(transport, "get_paginated", None)
        if not callable(get_paginated):
            return

        try:
            objects = list(get_paginated(_SERVICE_PRINCIPALS_PATH))
        except Exception as exc:  # noqa: BLE001 — degrade-to-empty is the contract
            _logger.info(
                "sieve: signed-id plane transport degraded to empty: %s", exc
            )
            return

        for obj in objects:
            if not isinstance(obj, dict):
                continue
            inc = self._object_to_incidence(obj, transport)
            if inc is not None:
                yield inc

    def _object_to_incidence(
        self, obj: Mapping[str, Any], transport: Any
    ) -> Incidence | None:
        """Build one ``Incidence`` from a directory service-principal object.

        Graph SP shape (the same fields Okta exposes under different names, which
        the transport normalizes): ``id`` (object id), ``appId`` (the signed
        OIDC subject / client id), ``displayName``, optional ``spiffeId`` /
        ``svid`` when a runtime workload identity is bound.
        """
        sp_object_id = _str_or_none(obj.get("id"))
        oidc_sub = _str_or_none(obj.get("appId")) or _str_or_none(obj.get("oidc_sub"))
        display_name = _str_or_none(obj.get("displayName")) or _str_or_none(
            obj.get("display_name")
        )
        spiffe_id = _str_or_none(obj.get("spiffeId")) or _str_or_none(
            obj.get("spiffe_id")
        ) or _str_or_none(obj.get("svid"))

        keys: dict[str, str] = {}
        if oidc_sub:
            keys[FootprintField.OIDC_SUB.value] = oidc_sub
        if spiffe_id:
            keys[FootprintField.SPIFFE_ID.value] = spiffe_id
        if sp_object_id:
            keys[FootprintField.SP_OBJECT_ID.value] = sp_object_id

        # An OAuth grant id (the bridging N1 split source). Prefer a grant carried
        # inline on the object; else fetch the SP's grant sub-collection.
        grant_id = self._first_grant_id(obj, sp_object_id, transport)
        if grant_id:
            keys[FootprintField.OAUTH_GRANT_ID.value] = grant_id

        # No usable key at all → cannot attribute the row; skip it (never raise).
        if not keys:
            return None

        attrs: dict[str, str] = {}
        if display_name:
            attrs["app_display_name"] = display_name
        account_enabled = obj.get("accountEnabled")
        if isinstance(account_enabled, bool):
            attrs["account_enabled"] = str(account_enabled).lower()
        sp_type = _str_or_none(obj.get("servicePrincipalType"))
        if sp_type:
            attrs["sp_type"] = sp_type

        # A bound SVID is a PROVEN runtime identity (a verified handshake); a
        # directory-only SP is PLATFORM_ATTESTED (trusted as far as the IdP).
        admissibility = (
            Admissibility.PROVEN if spiffe_id else Admissibility.PLATFORM_ATTESTED
        )

        footprint = FootprintVector.of(
            plane_id=PlaneId.SIGNED_ID, keys=keys, attrs=attrs
        )
        ref_id = sp_object_id or oidc_sub or display_name or "unknown"
        try:
            return Incidence(
                plane_id=PlaneId.SIGNED_ID,
                footprint=footprint,
                catchability=self._catchability,
                admissibility=admissibility,
                raw_evidence_ref=f"{self._evidence_label}:servicePrincipals/{ref_id}",
            )
        except ValueError:
            # Defensive: an out-of-range catchability injected by a verifier
            # degrades to a dropped row, never a raised exception.
            return None

    def _first_grant_id(
        self,
        obj: Mapping[str, Any],
        sp_object_id: str | None,
        transport: Any,
    ) -> str | None:
        """The OAuth2 permission-grant id for this SP, if any.

        Prefers a grant id carried inline on the object (the Okta normalized
        shape and any pre-expanded Graph object); else lazily fetches the SP's
        ``oauth2PermissionGrants`` sub-collection over the transport. A
        transport error there degrades to "no grant id" rather than dropping the
        whole identity — the SP is still a real signed sighting.
        """
        inline = _str_or_none(obj.get("oauth_grant_id")) or _str_or_none(
            obj.get("oauthGrantId")
        )
        if inline:
            return inline
        grants = obj.get("oauth2PermissionGrants")
        grant_id = _first_id_in(grants)
        if grant_id:
            return grant_id
        if not sp_object_id:
            return None
        get_paginated = getattr(transport, "get_paginated", None)
        if not callable(get_paginated):
            return None
        try:
            path = _OAUTH_GRANTS_PATH.format(sp_id=sp_object_id)
            for grant in get_paginated(path):
                if isinstance(grant, dict):
                    gid = _str_or_none(grant.get("id"))
                    if gid:
                        return gid
        except Exception as exc:  # noqa: BLE001 — degrade, keep the SP sighting
            _logger.info(
                "sieve: signed-id grant fetch degraded for sp %s: %s",
                sp_object_id,
                exc,
            )
        return None


def _str_or_none(value: Any) -> str | None:
    """Coerce to a non-empty stripped string, or ``None``."""
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _first_id_in(grants: Any) -> str | None:
    """First grant ``id`` from an inline list of grant objects, or ``None``."""
    if not isinstance(grants, (list, tuple)):
        return None
    for grant in grants:
        if isinstance(grant, dict):
            gid = _str_or_none(grant.get("id"))
            if gid:
                return gid
    return None


__all__ = ["IdentityIdpSensor", "SIGNED_ID_CATCHABILITY"]
