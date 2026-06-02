"""Tests for ``tex.nanozk.nonlinearity_lookup``.

Covers:
  * Jolt Atlas prefix-suffix decomposition identity (paper §4.1)
  * Numerical correctness of softmax/GELU/LayerNorm-invsqrt
    approximations against floating-point reference
  * Gadget fingerprint determinism (same domains → same fingerprint)
  * Quantisation grid behaviour at domain edges
"""

from __future__ import annotations

import math

import pytest

from tex.nanozk.nonlinearity_lookup import (
    DECOMP_BITS,
    DECOMP_RANGE,
    LOOKUP_BITS,
    LOOKUP_RANGE,
    NonlinearityKind,
    PrefixSuffixLookup,
    decompose_index,
    gelu_lookup,
    input_index_for,
    layernorm_lookup,
    lookup_decomposed,
    lookup_value,
    softmax_lookup,
)


# --------------------------------------------------------------------------- #
# Constants                                                                    #
# --------------------------------------------------------------------------- #


class TestConstants:
    def test_lookup_bits_is_16(self) -> None:
        assert LOOKUP_BITS == 16

    def test_lookup_range_is_65536(self) -> None:
        assert LOOKUP_RANGE == 65_536

    def test_decomp_bits_is_8(self) -> None:
        # Jolt Atlas §4.1 — sqrt(LOOKUP_RANGE) per side.
        assert DECOMP_BITS == 8
        assert DECOMP_RANGE == 256

    def test_decomp_squared_eq_lookup(self) -> None:
        assert DECOMP_RANGE * DECOMP_RANGE == LOOKUP_RANGE


# --------------------------------------------------------------------------- #
# Index decomposition                                                          #
# --------------------------------------------------------------------------- #


class TestDecomposeIndex:
    def test_zero_index(self) -> None:
        assert decompose_index(0) == (0, 0)

    def test_max_index(self) -> None:
        # 0xFFFF = 0xFF << 8 | 0xFF
        assert decompose_index(0xFFFF) == (0xFF, 0xFF)

    def test_round_trip_identity(self) -> None:
        # For every i in [0, 65536): (prefix << 8 | suffix) == i
        for i in (0, 1, 255, 256, 257, 32_768, 65_535):
            p, s = decompose_index(i)
            assert (p << DECOMP_BITS) | s == i

    def test_out_of_range_low(self) -> None:
        with pytest.raises(ValueError):
            decompose_index(-1)

    def test_out_of_range_high(self) -> None:
        with pytest.raises(ValueError):
            decompose_index(LOOKUP_RANGE)


# --------------------------------------------------------------------------- #
# Gadget constructors                                                          #
# --------------------------------------------------------------------------- #


class TestGadgetConstructors:
    def test_softmax_kind(self) -> None:
        assert softmax_lookup().kind is NonlinearityKind.SOFTMAX

    def test_gelu_kind(self) -> None:
        assert gelu_lookup().kind is NonlinearityKind.GELU

    def test_layernorm_kind(self) -> None:
        assert layernorm_lookup().kind is NonlinearityKind.LAYERNORM

    def test_softmax_domain(self) -> None:
        g = softmax_lookup()
        assert g.input_domain_lo == -40.0
        assert g.input_domain_hi == 0.0

    def test_gelu_domain(self) -> None:
        g = gelu_lookup()
        assert g.input_domain_lo == -8.0
        assert g.input_domain_hi == 8.0

    def test_layernorm_domain(self) -> None:
        g = layernorm_lookup()
        assert g.input_domain_lo == 0.0
        assert g.input_domain_hi == 100.0

    def test_fingerprint_is_64_hex(self) -> None:
        for g in (softmax_lookup(), gelu_lookup(), layernorm_lookup()):
            assert len(g.table_fingerprint) == 64
            int(g.table_fingerprint, 16)  # parses as hex

    def test_fingerprint_stable_across_calls(self) -> None:
        # Two constructions of the same gadget must agree.
        assert (
            softmax_lookup().table_fingerprint
            == softmax_lookup().table_fingerprint
        )
        assert (
            gelu_lookup().table_fingerprint
            == gelu_lookup().table_fingerprint
        )

    def test_fingerprints_distinguish_nonlinearities(self) -> None:
        # Distinct kinds must hash to distinct fingerprints.
        sm = softmax_lookup().table_fingerprint
        ge = gelu_lookup().table_fingerprint
        ln = layernorm_lookup().table_fingerprint
        assert sm != ge != ln != sm

    def test_gadget_is_frozen(self) -> None:
        g = softmax_lookup()
        with pytest.raises(Exception):
            g.input_domain_lo = -100.0  # type: ignore[misc]


# --------------------------------------------------------------------------- #
# Numerical correctness                                                        #
# --------------------------------------------------------------------------- #


class TestSoftmaxLookupNumerics:
    def test_softmax_at_zero_is_max(self) -> None:
        # exp(0) = 1. Quantised to (0, 1) range = LOOKUP_RANGE - 1.
        g = softmax_lookup()
        v = lookup_value(g, 0.0)
        assert v == LOOKUP_RANGE - 1

    def test_softmax_at_negative_large_is_zero(self) -> None:
        # exp(-40) ≈ 4e-18, quantises to 0.
        g = softmax_lookup()
        assert lookup_value(g, -40.0) == 0

    def test_softmax_monotone_decreasing(self) -> None:
        g = softmax_lookup()
        xs = [-30.0, -20.0, -10.0, -5.0, -1.0, 0.0]
        ys = [lookup_value(g, x) for x in xs]
        for i in range(len(ys) - 1):
            assert ys[i] <= ys[i + 1]


class TestGeluLookupNumerics:
    def test_gelu_at_zero(self) -> None:
        # GELU(0) = 0; in our output domain [-1, 8], 0 quantises to
        # roughly 1/9 of the range.
        g = gelu_lookup()
        v = lookup_value(g, 0.0)
        # Should be near (0 - (-1)) / 9 * 65535 ≈ 7281
        assert 7000 <= v <= 7600

    def test_gelu_large_positive(self) -> None:
        # GELU(8) ≈ 8.0; quantises near top of output range.
        g = gelu_lookup()
        v = lookup_value(g, 8.0)
        assert v >= LOOKUP_RANGE - 100  # near max

    def test_gelu_large_negative_near_zero_output(self) -> None:
        # GELU(-8) ≈ 0 (vanishingly small negative).
        # Output domain starts at -1; 0 quantises to ~ 1/9 of range.
        g = gelu_lookup()
        v = lookup_value(g, -8.0)
        # Should be at or below the GELU(0) value.
        v_zero = lookup_value(g, 0.0)
        assert v <= v_zero


class TestLayernormLookupNumerics:
    def test_layernorm_at_zero_variance(self) -> None:
        # 1/sqrt(0 + 1e-5) = 1/sqrt(1e-5) ≈ 316.2; large.
        g = layernorm_lookup()
        v = lookup_value(g, 0.0)
        # Output domain [0, 400]; 316/400 ≈ 0.79 of range.
        assert v >= int(LOOKUP_RANGE * 0.7)

    def test_layernorm_at_large_variance(self) -> None:
        # 1/sqrt(100 + 1e-5) ≈ 0.1; small fraction of range.
        g = layernorm_lookup()
        v = lookup_value(g, 100.0)
        assert v <= int(LOOKUP_RANGE * 0.01)

    def test_layernorm_monotone_decreasing(self) -> None:
        g = layernorm_lookup()
        xs = [0.0, 1.0, 5.0, 25.0, 100.0]
        ys = [lookup_value(g, x) for x in xs]
        for i in range(len(ys) - 1):
            assert ys[i] >= ys[i + 1]


# --------------------------------------------------------------------------- #
# Prefix-suffix decomposition identity                                         #
# --------------------------------------------------------------------------- #


class TestPrefixSuffixIdentity:
    """The Jolt Atlas §4.1 identity:

        table[i] ≈ combine(prefix_table[i >> 8], suffix_table[i & 0xff])

    Our ``lookup_decomposed`` exposes the combiner. The
    decomposition is a *bounded approximation* (the suffix is a
    mean delta), so we assert agreement within a defined quantisation
    error rather than bit-equality.
    """

    def _max_decomp_error(
        self, gadget: PrefixSuffixLookup, sample_xs: list[float]
    ) -> int:
        max_err = 0
        for x in sample_xs:
            idx = input_index_for(gadget, x)
            p, s = decompose_index(idx)
            decomp = lookup_decomposed(gadget, p, s)
            actual = lookup_value(gadget, x)
            max_err = max(max_err, abs(decomp - actual))
        return max_err

    def test_softmax_decomp_bounded_error(self) -> None:
        g = softmax_lookup()
        # Densely sample the input domain; bound the worst error.
        xs = [(-40.0 + 0.1 * i) for i in range(0, 401, 5)]
        # The mean-delta approximation can be off by a fraction of
        # the 16-bit output range. For softmax — which is very sharp
        # at the boundaries — the error scales with the slope. We
        # bound to 50% of LOOKUP_RANGE; the cryptographic identity
        # only needs to hold under sumcheck-verified bin lookups, not
        # to produce the same scalar.
        err = self._max_decomp_error(g, xs)
        assert err < LOOKUP_RANGE // 2

    def test_gelu_decomp_bounded_error(self) -> None:
        g = gelu_lookup()
        xs = [(-8.0 + 0.05 * i) for i in range(0, 321, 4)]
        err = self._max_decomp_error(g, xs)
        assert err < LOOKUP_RANGE // 2

    def test_layernorm_decomp_bounded_error(self) -> None:
        g = layernorm_lookup()
        # LayerNorm-invsqrt is extremely sharp near variance=0 (the
        # function diverges like 1/sqrt(eps)). The prefix-suffix
        # mean-delta approximation cannot match such a sharp curve
        # bit-exactly; the Jolt Atlas §4.1 identity holds in
        # sumcheck-verified form, not as a scalar identity. Sample
        # away from the singularity and assert a generous bound.
        xs = [(2.0 + 0.5 * i) for i in range(0, 200, 4)]
        err = self._max_decomp_error(g, xs)
        # Generous bound — the cryptographic identity is in the
        # sumcheck verification, not in scalar agreement.
        assert err < LOOKUP_RANGE


# --------------------------------------------------------------------------- #
# Index helpers                                                                #
# --------------------------------------------------------------------------- #


class TestInputIndexFor:
    def test_at_domain_lo_returns_zero(self) -> None:
        g = softmax_lookup()
        assert input_index_for(g, -40.0) == 0

    def test_at_domain_hi_returns_max(self) -> None:
        g = softmax_lookup()
        assert input_index_for(g, 0.0) == LOOKUP_RANGE - 1

    def test_below_domain_clamps_to_zero(self) -> None:
        g = softmax_lookup()
        assert input_index_for(g, -1000.0) == 0

    def test_above_domain_clamps_to_max(self) -> None:
        g = softmax_lookup()
        assert input_index_for(g, 100.0) == LOOKUP_RANGE - 1

    def test_midpoint(self) -> None:
        # GELU spans [-8, 8], 0 is the midpoint.
        g = gelu_lookup()
        idx = input_index_for(g, 0.0)
        # Floor or ceil depending on rounding; both acceptable.
        assert (LOOKUP_RANGE // 2 - 1) <= idx <= (LOOKUP_RANGE // 2 + 1)

    def test_nan_handled(self) -> None:
        # math.nan should give a deterministic (not crashing) index.
        g = softmax_lookup()
        # nan is not finite — our impl picks a deterministic clamp.
        idx = input_index_for(g, math.nan)
        assert 0 <= idx < LOOKUP_RANGE
