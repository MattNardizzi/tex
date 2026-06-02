"""
SCITT ARP — Attestation Reconciliation Protocol integration.

Reference
---------
draft-hillier-scitt-arp-00 (IETF), submitted 1 May 2026, expires
2 November 2026. ARP extends SCITT to deterministic, bilateral,
zero-knowledge-capable reconciliation across sovereign authoritative
registers without raw register records leaving their data-residency
jurisdiction.

Why this matters for ZKPROV
---------------------------
A multinational GPAI provider has training data spread across
multiple jurisdictions: EU-residency data anchored at the EU AI
Office's SCITT registry, US-residency data at NIST's, UK data at
the AISI's, and so on. The EU AI Act Article 53(1)(d) public
summary requires aggregating these without moving the underlying
data across borders. ARP is the standard that lets each
jurisdiction's register publish a *narrowed claim* (e.g. "this
manifest covers ≤N% EU-residency records under license L") and a
bilateral reconciliation step produces a single audit verdict
without leaking specifics.

What this module ships
----------------------
A bridge between Tex's ZKPROV commitments and the ARP wire format:

1. **NARROW** — project a ``DatasetManifest`` into a narrowed
   per-jurisdiction claim using the Predicate Taxonomy from
   ARP §4 (only the predicates that the EU AI Office's
   Transparency Chapter exposes for cross-sovereign exchange).
2. **PACKAGE** — wrap a narrowed claim in the ARP COSE-protected
   header structure (labels 0x801-0x804 from §6).
3. **VERIFY** — check that an ARP Reconciliation Output (the
   bilateral output from two ARP-aware verifiers) is consistent
   with a Tex commitment.

What this is NOT
----------------
A general SCITT registry implementation. Tex consumes the SCITT
architecture (draft-ietf-scitt-architecture-22) via
``tex.evidence.scitt_cose_alg`` and ``tex.vet.scitt``; ARP is the
*reconciliation layer on top* of that architecture. We only
generate the ARP claim payload here; the actual cross-sovereign
exchange happens between Transparency Service endpoints.

This is the third piece of the wedge no agent-governance competitor
has wired. Microsoft AGT, Noma, Zenity, Pillar — none of them touch
ARP. As of May 18 2026 the draft is 17 days old.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import Enum

from tex.zkprov.commitment import DatasetCommitment
from tex.zkprov.manifest import DatasetManifest


# --------------------------------------------------------------------------- #
# COSE labels per ARP §6 IANA Considerations                                  #
# --------------------------------------------------------------------------- #
#
# The draft requests IANA to register the following COSE protected-
# header labels in the 0x800 .. 0x8FF namespace:
#
#   0x801  arp-bilateral-agreement-hash
#   0x802  arp-policy-version-hash
#   0x803  arp-pattern-library-hash
#   0x804  arp-divergence-axis

ARP_BILATERAL_AGREEMENT_HASH = 0x801
ARP_POLICY_VERSION_HASH = 0x802
ARP_PATTERN_LIBRARY_HASH = 0x803
ARP_DIVERGENCE_AXIS = 0x804


class ARPPredicate(str, Enum):
    """Predicate taxonomy admissible for cross-sovereign exchange.

    The draft (§5) explicitly notes the Predicate Taxonomy SHOULD
    be designed such that the set of permitted narrowings is small
    enough that narrowing observation does not materially weaken
    subject privacy. The set below is the minimum useful set for
    Article 53(1)(d) reconciliation.
    """

    DATA_VOLUME_BUCKET = "data-volume-bucket"  # "<10GB", "10GB-1TB", ">1TB"
    LICENSE_FAMILY_PRESENT = "license-family-present"  # CC, Apache/MIT, proprietary
    JURISDICTION_RESIDENCY = "jurisdiction-residency"  # EU, US, UK, ...
    TEMPORAL_WINDOW_OVERLAP = "temporal-window-overlap"  # before/after a date
    MODEL_PROVIDER_DECLARATION = "model-provider-declaration"  # GPAI / non-GPAI


@dataclass(frozen=True, slots=True)
class NarrowedClaim:
    """ARP narrowed claim about a manifest, fit for cross-border share.

    The claim contains *no record-level information* — only the
    categorical predicates the Predicate Taxonomy permits.
    """

    manifest_root_hash: str  # public commitment reference
    predicate: ARPPredicate
    predicate_value: str  # e.g. "10GB-1TB", "CC", "EU"
    policy_version_hash: str
    pattern_library_hash: str
    divergence_axis: str  # ARP §4: which dimension this claim measures
    asserted_at: datetime

    def canonical_bytes(self) -> bytes:
        return json.dumps(
            {
                "manifest_root_hash": self.manifest_root_hash,
                "predicate": self.predicate.value,
                "predicate_value": self.predicate_value,
                "policy_version_hash": self.policy_version_hash,
                "pattern_library_hash": self.pattern_library_hash,
                "divergence_axis": self.divergence_axis,
                "asserted_at": self.asserted_at.astimezone(UTC).isoformat(),
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")


@dataclass(frozen=True, slots=True)
class ARPPredicateLibrary:
    """The pattern library a TS uses for narrowing.

    Each TS publishes its library hash so reconciliation peers can
    confirm they're using the same predicate set. Mismatched
    libraries result in an ARP "divergence" output.
    """

    library_id: str
    pattern_library_hash: str
    policy_version_hash: str

    @staticmethod
    def default() -> "ARPPredicateLibrary":
        """Tex's default library matching EU AI Office TDS Template."""
        # Hash these constants so library_hash stays deterministic
        # across deployments; bump library_id when the taxonomy changes.
        import hashlib

        lib_id = "tex-arp-eu-ai-office-tds-v1"
        lib_hash = hashlib.sha256(
            (lib_id + ":" + ",".join(sorted(p.value for p in ARPPredicate))).encode(
                "utf-8"
            )
        ).hexdigest()
        policy_hash = hashlib.sha256(
            b"tex-arp-policy-v1:eu-ai-act-article-53-1-d:2026-08-02"
        ).hexdigest()
        return ARPPredicateLibrary(
            library_id=lib_id,
            pattern_library_hash=lib_hash,
            policy_version_hash=policy_hash,
        )


# --------------------------------------------------------------------------- #
# Narrowing                                                                   #
# --------------------------------------------------------------------------- #

def narrow_manifest_data_volume(
    manifest: DatasetManifest,
    library: ARPPredicateLibrary,
) -> NarrowedClaim:
    """Produce a data-volume-bucket narrowed claim.

    The exact record counts are hidden; only the bucket label
    crosses the jurisdictional boundary. Buckets follow the EU AI
    Office's recommended thresholds.
    """
    total_records = sum(s.record_count for s in manifest.sources)
    if total_records < 10_000:
        bucket = "<10k"
    elif total_records < 1_000_000:
        bucket = "10k-1M"
    elif total_records < 100_000_000:
        bucket = "1M-100M"
    else:
        bucket = ">100M"

    return NarrowedClaim(
        manifest_root_hash=manifest.manifest_root_hash(),
        predicate=ARPPredicate.DATA_VOLUME_BUCKET,
        predicate_value=bucket,
        policy_version_hash=library.policy_version_hash,
        pattern_library_hash=library.pattern_library_hash,
        divergence_axis="record_count",
        asserted_at=datetime.now(UTC),
    )


def narrow_manifest_license_family(
    manifest: DatasetManifest,
    library: ARPPredicateLibrary,
) -> NarrowedClaim:
    """Produce a license-family-present narrowed claim.

    Per ARP §4, the value is a compact tag identifying which
    license families appear in the manifest (e.g. "CC,Apache,Proprietary")
    without revealing which sources fall under which family.
    """
    family_seen: set[str] = set()
    for src in manifest.sources:
        v = src.license.value
        if v.startswith("CC"):
            family_seen.add("CC")
        elif v in {"Apache-2.0", "MIT", "BSD-3-Clause"}:
            family_seen.add("Permissive")
        elif v.startswith("TDS:Proprietary"):
            family_seen.add("Proprietary")
        elif v.startswith("TDS:Scraped"):
            family_seen.add("Scraped")
        elif v.startswith("TDS:Synthetic"):
            family_seen.add("Synthetic")
        elif v.startswith("TDS:User-Data"):
            family_seen.add("UserData")
        else:
            family_seen.add("Other")

    return NarrowedClaim(
        manifest_root_hash=manifest.manifest_root_hash(),
        predicate=ARPPredicate.LICENSE_FAMILY_PRESENT,
        predicate_value=",".join(sorted(family_seen)),
        policy_version_hash=library.policy_version_hash,
        pattern_library_hash=library.pattern_library_hash,
        divergence_axis="license",
        asserted_at=datetime.now(UTC),
    )


def narrow_manifest_temporal_window(
    manifest: DatasetManifest,
    library: ARPPredicateLibrary,
    *,
    cutoff: datetime,
) -> NarrowedClaim:
    """Temporal-window narrowing relative to a cutoff date.

    Useful for "trained on data captured before/after 2025-06-01"
    kinds of regulatory questions. The exact training_window values
    are NOT crossed jurisdictionally; only the bucket relationship
    to ``cutoff``.
    """
    if cutoff.tzinfo is None:
        cutoff = cutoff.replace(tzinfo=UTC)
    end = manifest.training_window_end
    if end.tzinfo is None:
        end = end.replace(tzinfo=UTC)
    start = manifest.training_window_start
    if start.tzinfo is None:
        start = start.replace(tzinfo=UTC)

    if end < cutoff:
        bucket = "before-cutoff"
    elif start > cutoff:
        bucket = "after-cutoff"
    else:
        bucket = "spans-cutoff"

    return NarrowedClaim(
        manifest_root_hash=manifest.manifest_root_hash(),
        predicate=ARPPredicate.TEMPORAL_WINDOW_OVERLAP,
        predicate_value=f"{bucket}:{cutoff.astimezone(UTC).date().isoformat()}",
        policy_version_hash=library.policy_version_hash,
        pattern_library_hash=library.pattern_library_hash,
        divergence_axis="training_window",
        asserted_at=datetime.now(UTC),
    )


# --------------------------------------------------------------------------- #
# COSE-shaped packaging                                                       #
# --------------------------------------------------------------------------- #

def package_for_arp_exchange(
    claim: NarrowedClaim,
    *,
    bilateral_agreement_hash: str,
) -> dict[int, object]:
    """Build the COSE protected-header dict for an ARP exchange.

    Returns a dict keyed by integer COSE labels, consumable by
    cose-python or any other CBOR-COSE encoder. The Transparency
    Service implementation wraps this in COSE_Sign1 with the TS's
    signing key.

    ``bilateral_agreement_hash`` is the hash of the bilateral
    agreement document between the two reconciling jurisdictions.
    Per ARP §4, this is required so a passive observer cannot
    correlate exchanges across distinct bilateral relationships.
    """
    return {
        ARP_BILATERAL_AGREEMENT_HASH: bilateral_agreement_hash,
        ARP_POLICY_VERSION_HASH: claim.policy_version_hash,
        ARP_PATTERN_LIBRARY_HASH: claim.pattern_library_hash,
        ARP_DIVERGENCE_AXIS: claim.divergence_axis,
        # The payload itself goes in the COSE payload field; we
        # carry the canonical bytes alongside for callers that
        # want to inspect without a CBOR decoder.
        -1: claim.canonical_bytes(),  # Tex-private sidecar key
    }


# --------------------------------------------------------------------------- #
# Reconciliation outputs                                                      #
# --------------------------------------------------------------------------- #

class ARPReconciliationVerdict(str, Enum):
    """Possible outcomes of an ARP bilateral reconciliation.

    Per ARP §4:

    - AGREE: both registers' narrowed claims align under the
      bilateral agreement's predicate library.
    - DIVERGE: claims disagree on the divergence axis; the
      reconciliation output names the axis and the magnitude
      bucket of the disagreement (e.g. "data-volume-bucket
      differs by one bucket").
    - INCONCLUSIVE: at least one register's narrowed claim
      was not derivable under the agreed library; manual
      reconciliation required.
    """

    AGREE = "agree"
    DIVERGE = "diverge"
    INCONCLUSIVE = "inconclusive"


@dataclass(frozen=True, slots=True)
class ARPReconciliationOutput:
    """The output of a bilateral ARP exchange.

    Wire format follows the COSE-encoded
    application/arp-reconciliation-output+cbor media type from
    ARP §6 IANA. We model the same fields as a Python dataclass
    for downstream consumption by SCITT-aware callers.
    """

    bilateral_agreement_hash: str
    verdict: ARPReconciliationVerdict
    manifest_root_hash: str
    divergence_axis: str | None
    reconciliation_run_at: datetime


def consistent_with_commitment(
    output: ARPReconciliationOutput,
    commitment: DatasetCommitment,
) -> bool:
    """Whether a reconciliation output references the right commitment."""
    return (
        output.manifest_root_hash == commitment.manifest_root_hash
        and output.verdict is ARPReconciliationVerdict.AGREE
    )


__all__ = [
    "ARP_BILATERAL_AGREEMENT_HASH",
    "ARP_POLICY_VERSION_HASH",
    "ARP_PATTERN_LIBRARY_HASH",
    "ARP_DIVERGENCE_AXIS",
    "ARPPredicate",
    "ARPPredicateLibrary",
    "NarrowedClaim",
    "ARPReconciliationVerdict",
    "ARPReconciliationOutput",
    "narrow_manifest_data_volume",
    "narrow_manifest_license_family",
    "narrow_manifest_temporal_window",
    "package_for_arp_exchange",
    "consistent_with_commitment",
]
