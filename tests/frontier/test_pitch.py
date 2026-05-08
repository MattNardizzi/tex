"""
Tests for the Tex pitch package (Thread 9 — dual-ICP dossiers).

Coverage
--------
- Compliance corpus shape and content (FTC actions, regulatory
  anchors, CVE list, BlueRock figure).
- Deterministic intel helpers: same domain -> same result; different
  domains -> different results often enough; honest "no AI-SDR" path.
- BrandSafetyDossier: required fields, FTC count > 0, $24M judgments,
  EU/CA/NY anchors, Tex capability list non-empty.
- McpRiskDossier: all four canonical CVEs, BlueRock 0.367 carried,
  SSRF score in [base_fraction, 1.0], Tex runtime capability list
  non-empty.
- InsurerEvidencePacket: builds with all artifact slots, signature
  decodes, three canonical artifact names present.
- verify_insurer_evidence_packet (the independent verifier): valid
  round-trip; tampered artifact bytes -> DIGEST_MISMATCH; tampered
  signature -> SIGNATURE_INVALID; wrong public key -> SIGNATURE_INVALID;
  unaccepted algorithm -> UNACCEPTED_ALGORITHM; orphan digest;
  mangled base64.
- Backward-compat: 3-positional call without keyword args raises
  TypeError with a remediation message.
- Telemetry: events emit with expected fields.
"""

from __future__ import annotations

import base64
import hashlib
from datetime import UTC, datetime
from uuid import uuid4

import pytest

from tex.c2pa.manifest import C2paAssertion, C2paClaim, C2paManifest
from tex.domain.evidence import EvidenceRecord
from tex.events._canonical import canonical_json
from tex.pitch import (
    BLUEROCK_FLEET_SAMPLE_SIZE,
    BLUEROCK_SSRF_VULNERABLE_FRACTION,
    FTC_AI_COMPLY_TOTAL_MONETARY_JUDGMENTS_USD,
    FTC_OPERATION_AI_COMPLY,
    MARKETING_REGULATORY_ANCHORS,
    MCP_CVE_EXPOSURE,
    BrandSafetyDossier,
    InsurerEvidencePacket,
    McpRiskDossier,
    PacketVerificationResult,
    build_brand_safety_dossier,
    build_insurer_evidence_packet,
    build_mcp_risk_dossier,
    verify_insurer_evidence_packet,
)
from tex.pitch._intel import (
    derive_company_name,
    detect_mcp_runtime_footprint,
    estimate_ai_sdr_vendor,
    estimate_outbound_volume_per_month,
)
from tex.pitch.insurer_export import (
    _ARTIFACT_NAME_AUDIT_CHAIN,
    _ARTIFACT_NAME_C2PA,
    _ARTIFACT_NAME_RECEIPTS,
    _PACKET_LAYOUT_VERSION,
)
from tex.pqcrypto._ed25519_provider import Ed25519Provider
from tex.pqcrypto.algorithm_agility import (
    SignatureAlgorithm,
    SignatureKeyPair,
)
from tex.receipts.receipt import ToolExecutionReceipt


# -----------------------------------------------------------------------------
# fixtures
# -----------------------------------------------------------------------------


_PROVIDER = Ed25519Provider()


@pytest.fixture
def signing_key() -> SignatureKeyPair:
    return _PROVIDER.generate_keypair("test-key-pitch-thread9")


def _make_record(prev_hash: str | None) -> EvidenceRecord:
    payload_obj = {"verdict": "PERMIT", "ts": "2026-04-15T12:00:00Z"}
    payload_json = canonical_json(payload_obj)
    payload_sha256 = hashlib.sha256(payload_json.encode()).hexdigest()
    rh_input = (payload_sha256 + (prev_hash or "")).encode()
    return EvidenceRecord(
        decision_id=uuid4(),
        request_id=uuid4(),
        record_type="decision",
        payload_json=payload_json,
        payload_sha256=payload_sha256,
        previous_hash=prev_hash,
        record_hash=hashlib.sha256(rh_input).hexdigest(),
        policy_version="v1.0.0",
    )


@pytest.fixture
def evidence_records() -> tuple[EvidenceRecord, ...]:
    r1 = _make_record(None)
    r2 = _make_record(r1.record_hash)
    return (r1, r2)


@pytest.fixture
def c2pa_manifest() -> C2paManifest:
    claim = C2paClaim(
        title="email-001",
        format="message/rfc822",
        instance_id="urn:uuid:" + str(uuid4()),
        claim_generator="tex/2.0",
        claim_generator_info={"version": "2.0"},
        created_at=datetime.now(UTC),
        assertions=(
            C2paAssertion(
                label="c2pa.actions.v2",
                data={"action": "ai-generated", "model": "tex-test"},
            ),
        ),
    )
    return C2paManifest(claim=claim)


@pytest.fixture
def tool_receipt() -> ToolExecutionReceipt:
    return ToolExecutionReceipt(
        receipt_id="rcpt-thread9-fixture-id",
        session_id="sess-thread9",
        tool_name="search",
        tool_input_hash="a" * 64,
        tool_output_hash="b" * 64,
        result_count=3,
        started_at=datetime.now(UTC),
        completed_at=datetime.now(UTC),
        runtime_version="tex/2026.05.07-test",
        hmac_signature="c" * 64,
        hmac_key_id="k1",
    )


@pytest.fixture
def signed_packet(
    signing_key: SignatureKeyPair,
    evidence_records: tuple[EvidenceRecord, ...],
    c2pa_manifest: C2paManifest,
    tool_receipt: ToolExecutionReceipt,
) -> InsurerEvidencePacket:
    return build_insurer_evidence_packet(
        "tenant-acme",
        "2026-04-01T00:00:00Z",
        "2026-04-30T23:59:59Z",
        evidence_records=evidence_records,
        c2pa_manifests=(c2pa_manifest,),
        receipts=(tool_receipt,),
        signing_key=signing_key,
    )


# -----------------------------------------------------------------------------
# compliance corpus
# -----------------------------------------------------------------------------


class TestComplianceCorpus:
    def test_ftc_corpus_is_non_empty(self) -> None:
        assert len(FTC_OPERATION_AI_COMPLY) >= 5

    def test_ftc_corpus_total_matches_repo_canonical(self) -> None:
        # The headline pitch number is $24M. Source: the scaffolded TODO
        # in vp_marketing.py and FRONTIER_COMPLIANCE.md.
        assert FTC_AI_COMPLY_TOTAL_MONETARY_JUDGMENTS_USD == 24_000_000

    def test_marketing_anchors_include_eu_ca_ny(self) -> None:
        citations = " | ".join(a.citation for a in MARKETING_REGULATORY_ANCHORS)
        assert "EU AI Act Art. 50" in citations
        assert "California SB 942" in citations
        assert "New York" in citations
        assert "FTC Act §5" in citations

    def test_marketing_anchor_dates_match_compliance_md(self) -> None:
        by_cite = {a.citation: a for a in MARKETING_REGULATORY_ANCHORS}
        # FRONTIER_COMPLIANCE.md: EU AI Act Art. 50 applicable from 2 Aug 2026
        eu = by_cite["EU AI Act Art. 50 (Transparency for AI-generated content)"]
        assert eu.operative_date.isoformat() == "2026-08-02"
        # SB 942 operative 2 Aug 2026 per AB 853
        ca = by_cite["California SB 942 (CAITA), as amended by AB 853"]
        assert ca.operative_date.isoformat() == "2026-08-02"

    def test_mcp_cve_corpus_has_exactly_four_canonical_cves(self) -> None:
        ids = {c.cve_id for c in MCP_CVE_EXPOSURE}
        assert ids == {
            "CVE-2025-49596",
            "CVE-2026-22252",
            "CVE-2025-54136",
            "CVE-2026-22688",
        }

    def test_bluerock_constants_match_repo_canonical(self) -> None:
        # FRONTIER_KNOWN_BYPASSES.md: 36.7% of 7,000+ MCP servers SSRF-vuln
        assert BLUEROCK_SSRF_VULNERABLE_FRACTION == pytest.approx(0.367)
        assert BLUEROCK_FLEET_SAMPLE_SIZE >= 7_000


# -----------------------------------------------------------------------------
# intel helpers
# -----------------------------------------------------------------------------


class TestIntelHelpers:
    def test_company_name_derivation(self) -> None:
        assert derive_company_name("acmecorp.com") == "Acmecorp"
        assert derive_company_name("HTTPS://Foo.IO/") == "Foo"

    def test_company_name_empty_raises(self) -> None:
        with pytest.raises(ValueError):
            derive_company_name("")

    def test_vendor_estimate_is_deterministic(self) -> None:
        a1 = estimate_ai_sdr_vendor("acmecorp.com")
        a2 = estimate_ai_sdr_vendor("acmecorp.com")
        assert a1 == a2

    def test_vendor_estimate_can_return_none(self) -> None:
        # Sweep ~200 domains; expect ~10% None and most non-None.
        vendors = [
            estimate_ai_sdr_vendor(f"company-{i}.example") for i in range(200)
        ]
        assert any(v is None for v in vendors)
        assert any(v is not None for v in vendors)

    def test_outbound_volume_in_expected_band(self) -> None:
        for i in range(100):
            v = estimate_outbound_volume_per_month(f"co-{i}.example")
            assert 5_000 <= v <= 250_000
            assert v % 5_000 == 0

    def test_mcp_footprint_always_non_empty(self) -> None:
        for i in range(100):
            fp = detect_mcp_runtime_footprint(f"co-{i}.example")
            assert len(fp) >= 1
            assert len(fp) <= 5

    def test_mcp_footprint_no_duplicates(self) -> None:
        for i in range(100):
            fp = detect_mcp_runtime_footprint(f"co-{i}.example")
            assert len(set(fp)) == len(fp)


# -----------------------------------------------------------------------------
# brand safety dossier (VP Marketing)
# -----------------------------------------------------------------------------


class TestBrandSafetyDossier:
    def test_basic_shape(self) -> None:
        d = build_brand_safety_dossier(company_domain="acmecorp.com")
        assert isinstance(d, BrandSafetyDossier)
        assert d.company_name == "Acmecorp"
        assert d.estimated_outbound_volume_per_month > 0
        assert len(d.tex_evidence_capabilities) >= 3

    def test_dossier_cites_real_ftc_enforcement_count(self) -> None:
        d = build_brand_safety_dossier(company_domain="acmecorp.com")
        # Acceptance criterion: "real FTC enforcement counts"
        assert len(d.enforcement_actions) >= 5
        # And the headline $ figure carried
        assert d.total_monetary_judgments_usd == 24_000_000

    def test_dossier_summary_includes_eu_and_ca_dates(self) -> None:
        d = build_brand_safety_dossier(company_domain="acmecorp.com")
        assert "2026-08-02" in d.enforcement_exposure_summary

    def test_dossier_is_deterministic(self) -> None:
        a = build_brand_safety_dossier(company_domain="acmecorp.com")
        b = build_brand_safety_dossier(company_domain="acmecorp.com")
        assert a == b

    def test_dossier_is_frozen(self) -> None:
        d = build_brand_safety_dossier(company_domain="acmecorp.com")
        with pytest.raises(Exception):  # FrozenInstanceError
            d.company_name = "Other"  # type: ignore[misc]

    def test_dossier_handles_no_vendor_path(self) -> None:
        # Find a domain whose deterministic seed yields None
        domain = next(
            f"company-{i}.example"
            for i in range(500)
            if estimate_ai_sdr_vendor(f"company-{i}.example") is None
        )
        d = build_brand_safety_dossier(company_domain=domain)
        assert d.detected_ai_sdr_vendor is None
        assert "no detected AI-SDR" in d.enforcement_exposure_summary


# -----------------------------------------------------------------------------
# mcp risk dossier (CISO)
# -----------------------------------------------------------------------------


class TestMcpRiskDossier:
    def test_basic_shape(self) -> None:
        d = build_mcp_risk_dossier(company_domain="acmecorp.com")
        assert isinstance(d, McpRiskDossier)
        assert d.company_name == "Acmecorp"
        assert len(d.tex_runtime_capabilities) >= 3

    def test_dossier_cites_all_four_canonical_cves(self) -> None:
        d = build_mcp_risk_dossier(company_domain="acmecorp.com")
        assert set(d.cve_exposure) == {
            "CVE-2025-49596",
            "CVE-2026-22252",
            "CVE-2025-54136",
            "CVE-2026-22688",
        }

    def test_dossier_carries_bluerock_figure_verbatim(self) -> None:
        d = build_mcp_risk_dossier(company_domain="acmecorp.com")
        assert d.bluerock_ssrf_fraction == pytest.approx(0.367)
        assert d.bluerock_fleet_sample_size >= 7_000

    def test_ssrf_score_floor_is_bluerock_baseline(self) -> None:
        # For any domain, score must be >= 0.367 (the headline) and <= 1.0
        for i in range(50):
            d = build_mcp_risk_dossier(company_domain=f"co-{i}.example")
            assert 0.367 <= d.ssrf_risk_score <= 1.0

    def test_ssrf_score_rises_with_vulnerable_runtime(self) -> None:
        # "Anthropic MCP Inspector" matches a known CVE class — must
        # produce a score strictly above the baseline.
        scores = []
        for i in range(50):
            d = build_mcp_risk_dossier(company_domain=f"co-{i}.example")
            if any(
                "MCP Inspector" in r or "LibreChat" in r or "Cursor" in r or "WeKnora" in r
                for r in d.detected_mcp_servers
            ):
                scores.append(d.ssrf_risk_score)
        assert scores, "expected at least one footprint to include a CVE class"
        assert all(s > 0.367 for s in scores)

    def test_dossier_is_deterministic(self) -> None:
        a = build_mcp_risk_dossier(company_domain="acmecorp.com")
        b = build_mcp_risk_dossier(company_domain="acmecorp.com")
        assert a == b

    def test_ssrf_score_with_empty_footprint_returns_baseline(self) -> None:
        """
        Direct unit test of the defensive branch in ``_ssrf_risk_score``.

        ``detect_mcp_runtime_footprint`` always returns >=1 entry by
        construction, so this branch is unreachable through the public
        API. It exists as a safety net for future thread paths that
        synthesize a footprint from live signals.
        """
        from tex.pitch.ciso import _ssrf_risk_score
        assert _ssrf_risk_score((), base_fraction=0.367) == 0.367


# -----------------------------------------------------------------------------
# insurer evidence packet
# -----------------------------------------------------------------------------


class TestInsurerEvidencePacketBuild:
    def test_packet_basic_shape(
        self, signed_packet: InsurerEvidencePacket
    ) -> None:
        assert signed_packet.tenant_id == "tenant-acme"
        assert signed_packet.algorithm is SignatureAlgorithm.ED25519
        assert signed_packet.layout_version == _PACKET_LAYOUT_VERSION
        assert set(signed_packet.artifacts.keys()) == {
            _ARTIFACT_NAME_AUDIT_CHAIN,
            _ARTIFACT_NAME_C2PA,
            _ARTIFACT_NAME_RECEIPTS,
        }
        # Digest map parallels artifact map
        assert set(signed_packet.artifact_digests.keys()) == set(
            signed_packet.artifacts.keys()
        )

    def test_packet_signature_is_base64(
        self, signed_packet: InsurerEvidencePacket
    ) -> None:
        decoded = base64.b64decode(
            signed_packet.manifest_signature_b64, validate=True
        )
        # Ed25519 sigs are exactly 64 bytes
        assert len(decoded) == 64

    def test_packet_digests_match_recomputed(
        self, signed_packet: InsurerEvidencePacket
    ) -> None:
        for name, data in signed_packet.artifacts.items():
            assert (
                hashlib.sha256(data).hexdigest()
                == signed_packet.artifact_digests[name]
            )

    def test_packet_three_arg_form_raises(
        self, signing_key: SignatureKeyPair
    ) -> None:
        # Backward-compat: original 3-positional signature must still
        # be callable, but raise a clear TypeError with remediation.
        with pytest.raises(TypeError, match="evidence_records"):
            build_insurer_evidence_packet("t", "s", "e")

    def test_packet_partial_kwargs_raises(
        self,
        signing_key: SignatureKeyPair,
        evidence_records: tuple[EvidenceRecord, ...],
    ) -> None:
        with pytest.raises(TypeError):
            build_insurer_evidence_packet(
                "t", "s", "e",
                evidence_records=evidence_records,
                # missing c2pa_manifests, receipts, signing_key
            )


# -----------------------------------------------------------------------------
# verifier (acceptance criterion: round-trip)
# -----------------------------------------------------------------------------


def _replace(packet: InsurerEvidencePacket, **changes) -> InsurerEvidencePacket:
    """Helper to mutate a frozen dataclass for tamper tests."""
    base = {
        "tenant_id": packet.tenant_id,
        "period_start_iso": packet.period_start_iso,
        "period_end_iso": packet.period_end_iso,
        "algorithm": packet.algorithm,
        "layout_version": packet.layout_version,
        "artifacts": packet.artifacts,
        "artifact_digests": packet.artifact_digests,
        "manifest_signature_b64": packet.manifest_signature_b64,
        "signing_public_key": packet.signing_public_key,
    }
    base.update(changes)
    return InsurerEvidencePacket(**base)


class TestPacketRoundTrip:
    def test_round_trip_valid(
        self, signed_packet: InsurerEvidencePacket
    ) -> None:
        result = verify_insurer_evidence_packet(signed_packet)
        assert isinstance(result, PacketVerificationResult)
        assert result.is_valid is True
        assert result.issue_count == 0
        assert result.algorithm is SignatureAlgorithm.ED25519
        assert result.artifact_count == 3

    def test_round_trip_with_pinned_public_key(
        self, signed_packet: InsurerEvidencePacket
    ) -> None:
        result = verify_insurer_evidence_packet(
            signed_packet, expected_public_key=signed_packet.signing_public_key
        )
        assert result.is_valid is True

    def test_pinned_key_mismatch_fails(
        self, signed_packet: InsurerEvidencePacket
    ) -> None:
        result = verify_insurer_evidence_packet(
            signed_packet, expected_public_key=b"not the real key"
        )
        assert result.is_valid is False
        assert any(i.code == "PUBLIC_KEY_PIN_MISMATCH" for i in result.issues)


class TestPacketTamperDetection:
    def test_tampered_artifact_bytes_yields_digest_mismatch(
        self, signed_packet: InsurerEvidencePacket
    ) -> None:
        # Flip a byte in audit_chain bytes; digest map untouched.
        tampered_artifacts = dict(signed_packet.artifacts)
        original = tampered_artifacts[_ARTIFACT_NAME_AUDIT_CHAIN]
        tampered_artifacts[_ARTIFACT_NAME_AUDIT_CHAIN] = original + b" "
        tampered = _replace(signed_packet, artifacts=tampered_artifacts)
        result = verify_insurer_evidence_packet(tampered)
        assert result.is_valid is False
        assert any(i.code == "DIGEST_MISMATCH" for i in result.issues)

    def test_tampered_signature_yields_signature_invalid(
        self, signed_packet: InsurerEvidencePacket
    ) -> None:
        # Replace signature with a valid-base64 but wrong-bytes signature.
        bogus = base64.b64encode(b"\x00" * 64).decode("ascii")
        tampered = _replace(signed_packet, manifest_signature_b64=bogus)
        result = verify_insurer_evidence_packet(tampered)
        assert result.is_valid is False
        assert any(i.code == "SIGNATURE_INVALID" for i in result.issues)

    def test_wrong_public_key_yields_signature_invalid(
        self, signed_packet: InsurerEvidencePacket,
        signing_key: SignatureKeyPair,
    ) -> None:
        # Generate a fresh, unrelated keypair and substitute its public key.
        other = _PROVIDER.generate_keypair("other")
        tampered = _replace(signed_packet, signing_public_key=other.public_key)
        result = verify_insurer_evidence_packet(tampered)
        assert result.is_valid is False
        # The verifier may report SIGNATURE_INVALID or VERIFIER_RAISED
        # depending on how the underlying primitive reacts to a mismatched
        # key; both are correct fail-closed outcomes.
        codes = {i.code for i in result.issues}
        assert codes & {"SIGNATURE_INVALID", "VERIFIER_RAISED"}

    def test_tampered_manifest_metadata_yields_signature_invalid(
        self, signed_packet: InsurerEvidencePacket
    ) -> None:
        # Change tenant_id without re-signing -> manifest no longer matches.
        tampered = _replace(signed_packet, tenant_id="evil-tenant")
        result = verify_insurer_evidence_packet(tampered)
        assert result.is_valid is False
        assert any(i.code == "SIGNATURE_INVALID" for i in result.issues)

    def test_orphan_digest_detected(
        self, signed_packet: InsurerEvidencePacket
    ) -> None:
        # Add a digest with no corresponding artifact bytes.
        digests = dict(signed_packet.artifact_digests)
        digests["ghost"] = "0" * 64
        tampered = _replace(signed_packet, artifact_digests=digests)
        result = verify_insurer_evidence_packet(tampered)
        assert result.is_valid is False
        codes = [i.code for i in result.issues]
        # An extra digest changes the signed manifest, so SIGNATURE_INVALID
        # also surfaces — but we specifically want ORPHAN_DIGEST flagged so
        # forensics gets a clear root-cause.
        assert "ORPHAN_DIGEST" in codes

    def test_missing_digest_for_artifact_detected(
        self, signed_packet: InsurerEvidencePacket
    ) -> None:
        digests = dict(signed_packet.artifact_digests)
        digests.pop(_ARTIFACT_NAME_AUDIT_CHAIN)
        tampered = _replace(signed_packet, artifact_digests=digests)
        result = verify_insurer_evidence_packet(tampered)
        assert result.is_valid is False
        assert any(i.code == "MISSING_DIGEST" for i in result.issues)

    def test_mangled_base64_signature_detected(
        self, signed_packet: InsurerEvidencePacket
    ) -> None:
        tampered = _replace(
            signed_packet, manifest_signature_b64="!!!not-base64!!!"
        )
        result = verify_insurer_evidence_packet(tampered)
        assert result.is_valid is False
        assert any(
            i.code == "SIGNATURE_DECODE_FAIL" for i in result.issues
        )

    def test_unaccepted_algorithm_rejected(
        self, signed_packet: InsurerEvidencePacket
    ) -> None:
        # SLH-DSA is in the enum but not in the accepted set (and would
        # raise NotImplementedError in dispatch). Verifier must fail
        # closed before it ever calls the provider.
        tampered = _replace(
            signed_packet, algorithm=SignatureAlgorithm.SLH_DSA_128S
        )
        result = verify_insurer_evidence_packet(tampered)
        assert result.is_valid is False
        assert any(i.code == "UNACCEPTED_ALGORITHM" for i in result.issues)


# -----------------------------------------------------------------------------
# telemetry
# -----------------------------------------------------------------------------


class TestTelemetry:
    """
    Telemetry verification.

    The ``tex`` logger has ``propagate=False`` so pytest's ``caplog``
    (which hooks the root logger) cannot see structured events. We
    patch ``emit_event`` at each call site instead — this is the same
    technique the existing `tex.observability` test suite uses.
    """

    def _capture_emit(
        self, monkeypatch: pytest.MonkeyPatch, *modules: str
    ) -> list[tuple[str, dict]]:
        """Patch emit_event in the named modules; return capture list."""
        captured: list[tuple[str, dict]] = []

        def fake_emit(event: str, **fields) -> None:
            captured.append((event, dict(fields)))

        for mod in modules:
            monkeypatch.setattr(f"{mod}.emit_event", fake_emit)
        return captured

    def test_brand_safety_dossier_emits_event(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        captured = self._capture_emit(monkeypatch, "tex.pitch.vp_marketing")
        build_brand_safety_dossier(company_domain="telemetry.example")
        events = [e for e in captured if e[0] == "pitch.dossier.built"]
        assert len(events) == 1
        _, fields = events[0]
        assert fields["dossier_kind"] == "brand_safety"
        assert fields["company_domain"] == "telemetry.example"
        assert fields["enforcement_actions_count"] >= 5

    def test_mcp_risk_dossier_emits_event(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        captured = self._capture_emit(monkeypatch, "tex.pitch.ciso")
        build_mcp_risk_dossier(company_domain="telemetry.example")
        events = [e for e in captured if e[0] == "pitch.dossier.built"]
        assert len(events) == 1
        _, fields = events[0]
        assert fields["dossier_kind"] == "mcp_risk"
        assert fields["cve_count"] == 4

    def test_packet_build_emits_event(
        self,
        monkeypatch: pytest.MonkeyPatch,
        signing_key: SignatureKeyPair,
        evidence_records: tuple[EvidenceRecord, ...],
        c2pa_manifest: C2paManifest,
        tool_receipt: ToolExecutionReceipt,
    ) -> None:
        captured = self._capture_emit(monkeypatch, "tex.pitch.insurer_export")
        build_insurer_evidence_packet(
            "tenant-x", "2026-04-01", "2026-04-30",
            evidence_records=evidence_records,
            c2pa_manifests=(c2pa_manifest,),
            receipts=(tool_receipt,),
            signing_key=signing_key,
        )
        events = [e for e in captured if e[0] == "pitch.evidence_packet.built"]
        assert len(events) == 1
        _, fields = events[0]
        assert fields["tenant_id"] == "tenant-x"
        assert fields["algorithm"] == "ed25519"
        assert fields["evidence_record_count"] == 2

    def test_verify_emits_event(
        self,
        monkeypatch: pytest.MonkeyPatch,
        signed_packet: InsurerEvidencePacket,
    ) -> None:
        captured = self._capture_emit(monkeypatch, "tex.pitch.verifier")
        verify_insurer_evidence_packet(signed_packet)
        events = [e for e in captured if e[0] == "pitch.evidence_packet.verified"]
        assert len(events) == 1
        _, fields = events[0]
        assert fields["is_valid"] is True
        assert fields["issue_count"] == 0
