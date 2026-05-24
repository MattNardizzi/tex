"""Tests for tex.nanozk.logup_star — Logup* indexed lookup argument."""

from __future__ import annotations


import pytest

from tex.nanozk.logup_star import (
    DEFAULT_LOOKUP_ARGUMENT,
    LogupStarTranscript,
    LookupArgumentKind,
    logup_star_argue,
    logup_star_verify,
    logup_star_witness_count_no_extra_columns,
)


class TestLookupArgumentKind:
    def test_default_is_logup_star(self) -> None:
        assert DEFAULT_LOOKUP_ARGUMENT == LookupArgumentKind.LOGUP_STAR_2025_946

    def test_distinct_from_logup_gkr(self) -> None:
        assert (
            LookupArgumentKind.LOGUP_STAR_2025_946
            != LookupArgumentKind.LOGUP_GKR_2023_1284
        )

    def test_values_are_canonical_strings(self) -> None:
        assert (
            LookupArgumentKind.LOGUP_STAR_2025_946.value
            == "logup-star-2025-946"
        )


class TestLogupStarArgue:
    def test_argue_returns_transcript_with_default_kind(self) -> None:
        t = logup_star_argue(
            table_fingerprint="a" * 64,
            table_size=256,
            indices=[0, 1, 2, 255, 0],
        )
        assert isinstance(t, LogupStarTranscript)
        assert t.argument_kind == LookupArgumentKind.LOGUP_STAR_2025_946

    def test_argue_is_deterministic(self) -> None:
        t1 = logup_star_argue(
            table_fingerprint="a" * 64,
            table_size=256,
            indices=[0, 1, 2],
        )
        t2 = logup_star_argue(
            table_fingerprint="a" * 64,
            table_size=256,
            indices=[0, 1, 2],
        )
        assert t1 == t2

    def test_argue_changes_with_indices(self) -> None:
        t1 = logup_star_argue(
            table_fingerprint="a" * 64,
            table_size=256,
            indices=[0, 1, 2],
        )
        t2 = logup_star_argue(
            table_fingerprint="a" * 64,
            table_size=256,
            indices=[0, 1, 3],
        )
        assert t1.multiplicity_commitment != t2.multiplicity_commitment

    def test_argue_changes_with_table_fingerprint(self) -> None:
        t1 = logup_star_argue(
            table_fingerprint="a" * 64,
            table_size=256,
            indices=[0],
        )
        t2 = logup_star_argue(
            table_fingerprint="b" * 64,
            table_size=256,
            indices=[0],
        )
        assert t1.challenge != t2.challenge

    def test_argue_rejects_out_of_range_index(self) -> None:
        with pytest.raises(ValueError):
            logup_star_argue(
                table_fingerprint="a" * 64,
                table_size=256,
                indices=[256],
            )

    def test_argue_rejects_negative_table_size(self) -> None:
        with pytest.raises(ValueError):
            logup_star_argue(
                table_fingerprint="a" * 64,
                table_size=0,
                indices=[],
            )

    def test_argue_empty_indices(self) -> None:
        t = logup_star_argue(
            table_fingerprint="a" * 64,
            table_size=256,
            indices=[],
        )
        assert isinstance(t, LogupStarTranscript)


class TestLogupStarVerify:
    def test_round_trip_verifies(self) -> None:
        t = logup_star_argue(
            table_fingerprint="a" * 64,
            table_size=256,
            indices=[0, 1, 2, 255, 0],
        )
        assert logup_star_verify(
            t,
            table_fingerprint="a" * 64,
            table_size=256,
            indices=[0, 1, 2, 255, 0],
        ) is True

    def test_fails_on_table_fingerprint_mismatch(self) -> None:
        t = logup_star_argue(
            table_fingerprint="a" * 64,
            table_size=256,
            indices=[0],
        )
        assert logup_star_verify(
            t,
            table_fingerprint="b" * 64,
            table_size=256,
            indices=[0],
        ) is False

    def test_fails_on_indices_mismatch(self) -> None:
        t = logup_star_argue(
            table_fingerprint="a" * 64,
            table_size=256,
            indices=[0, 1],
        )
        assert logup_star_verify(
            t,
            table_fingerprint="a" * 64,
            table_size=256,
            indices=[0, 2],
        ) is False

    def test_fails_when_argument_kind_replaced(self) -> None:
        t = logup_star_argue(
            table_fingerprint="a" * 64,
            table_size=256,
            indices=[0],
        )
        bad = t.model_copy(
            update={
                "argument_kind": LookupArgumentKind.LOGUP_GKR_2023_1284
            }
        )
        assert logup_star_verify(
            bad,
            table_fingerprint="a" * 64,
            table_size=256,
            indices=[0],
        ) is False

    def test_fails_on_tampered_sum_tag(self) -> None:
        t = logup_star_argue(
            table_fingerprint="a" * 64,
            table_size=256,
            indices=[0],
        )
        bad = t.model_copy(update={"sum_tag": b"\xff" * 32})
        assert logup_star_verify(
            bad,
            table_fingerprint="a" * 64,
            table_size=256,
            indices=[0],
        ) is False

    def test_fails_on_oob_indices_during_verify(self) -> None:
        t = logup_star_argue(
            table_fingerprint="a" * 64,
            table_size=256,
            indices=[0],
        )
        # Pass out-of-range indices to verify -> caught fail-closed.
        assert logup_star_verify(
            t,
            table_fingerprint="a" * 64,
            table_size=256,
            indices=[300],
        ) is False


class TestInvariants:
    def test_invariant_says_no_indexing_array_commits(self) -> None:
        inv = logup_star_witness_count_no_extra_columns(
            table_size=256, indices_count=100_000
        )
        assert inv["size_indices_commits"] == 0
        assert inv["size_table_commits"] == 1
        assert inv["logup_gkr_size_indices_commits"] == 1

    def test_invariant_reports_savings(self) -> None:
        inv = logup_star_witness_count_no_extra_columns(
            table_size=256, indices_count=1_000_000
        )
        assert inv["saved_bytes_at_32_bytes_per_field_element"] == 32_000_000


class TestShimKeyEnvOverride:
    def test_env_override_changes_commitments(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv("TEX_LOGUP_SHIM_KEY", raising=False)
        t1 = logup_star_argue(
            table_fingerprint="a" * 64,
            table_size=256,
            indices=[0],
        )
        monkeypatch.setenv("TEX_LOGUP_SHIM_KEY", "alternate-test-key")
        t2 = logup_star_argue(
            table_fingerprint="a" * 64,
            table_size=256,
            indices=[0],
        )
        assert t1.multiplicity_commitment != t2.multiplicity_commitment
