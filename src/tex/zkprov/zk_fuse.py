"""
Zero-knowledge proof of the PDP decision-relation **fuse kernel**.

This is the defensible novelty in L1 — and the reason it is NOT the prior art.
The statement proven here is not "a subject's attributes satisfy a predicate"
(Di Francesco Maesa et al., JNCA 2023; the on-chain private-attribute XACML /
ZKP-CapBAC line, retrieved this session) and not "a generic computation ran
correctly" (Nchain US12273324B2). It is specifically the **verdict
computation**:

    PUBLIC:  policy weights wᵢ, the public fused score ``fused_q``, ``scale``
    PRIVATE: the per-stream risk scores sᵢ (which specialist flagged what)
    CLAIM:   ``fused_q`` is exactly the round-half-up, clamped, policy-weighted
             fusion ``clamp(round(Σ wᵢ·sᵢ / scale))`` of in-range private scores.

It is proven with the discrete-log Σ-protocol toolkit in ``schnorr_group`` —
Pedersen commitments to each private score, a homomorphic accumulation
``C_acc = Π Cᵢ^{wᵢ}`` the verifier recomputes from the public weights, and a
range proof that pins the rounding window. The whole proof is:

  * **hiding** — the verifier learns nothing about the individual sᵢ beyond the
    public ``fused_q`` (perfectly-hiding Pedersen + HVZK Σ-protocols);
  * **sound** — a forged ``fused_q`` makes the window range proof unsatisfiable
    (discrete-log binding + special soundness, error 2^-128);
  * **offline + no trusted hardware** — pure integer modexp + SHA-3, no
    blockchain, no enclave, no SRS ceremony (the two properties L1 must
    preserve);
  * **publicly verifiable, no shared secret** — the asymmetry the symmetric
    keyed-hash stand-in (the old default backend) lacked.

Scope honesty (cite exactly this, no more):
  * Proves the **fuse arithmetic** (weighted sum → ``fused_q`` binding) over
    private, range-bounded scores. The threshold map, the structural deny-floor,
    the quarantine pin and the monotone-lowering chain operate over PUBLIC
    fields and are checked deterministically by ``arbiter.evaluate_relation`` —
    they are NOT inside this ZK proof, by design (they are structural facts, not
    sensitive signals). Do not describe this as a ZK proof of the whole verdict.
  * Per-score range is proven to ``[0, 2^SCORE_BITS)`` ⊇ the score domain
    ``[0, scale]`` (a documented over-approximation — tightening to exactly
    ``[0, scale]`` is one ``prove_window`` call away). The verdict-critical
    rounding window IS tight, so this looseness can never change a verdict.
  * Maturity ``research-early``: a hand-rolled, unaudited 2048-bit (~112-bit,
    pre-quantum) construction. Real, but not "audited / certified".
"""

from __future__ import annotations

import json

from tex.zkprov import schnorr_group as sg

SCHEME = "schnorr-fuse-zk-v1"

# Score domain is [0, scale]; scale = 10**4 needs 14 bits, so [0, 2^14) ⊇
# [0, 10000]. The window proofs choose their own (tight) bit widths.
SCORE_BITS = 14


# ── public statement / errors ────────────────────────────────────────────────


class FuseProofError(ValueError):
    """The fuse statement cannot be honestly proven (e.g. inputs out of range,
    or a public/private inconsistency). Raised by the prover only — the verifier
    never raises, it returns False."""


def _ctx_bytes(scale: int, fused_q: int, weights: list[tuple[str, int]], commitments: list[int]) -> bytes:
    """Canonical public context every Fiat–Shamir challenge binds: scale, the
    public verdict-score, the contributing (name, weight) pairs, and every
    top-level score commitment. Stable-JSON idiom (sort_keys/compact)."""
    return json.dumps(
        {
            "scheme": SCHEME,
            "scale": scale,
            "fused_q": fused_q,
            "weights": [[n, w] for n, w in weights],
            "commitments": [int(c) for c in commitments],
            "p": sg.P,
            "g": sg.G,
            "h": sg.H,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


# ── window helpers (tight [0, width) via complement; one-sided [0, 2^bits)) ──


def _bits_for(width: int) -> int:
    """Smallest ``b`` with ``2^b >= width`` (so a b-bit range covers [0,width))."""
    return max(1, (width - 1).bit_length())


def _prove_window(value: int, randomness: int, width: int, ctx: bytes, label: bytes) -> dict:
    """Prove ``commit(value, randomness)`` opens to a value in ``[0, width)``,
    tightly, via two complementary range proofs (v ≥ 0 and width-1-v ≥ 0)."""
    if not (0 <= value < width):
        raise FuseProofError(f"window value {value} not in [0,{width})")
    bits = _bits_for(width)
    lo = sg.prove_range(value, randomness, bits, ctx, label + b"|lo")
    comp = width - 1 - value
    hi = sg.prove_range(comp, (-randomness) % sg.Q, bits, ctx, label + b"|hi")
    return {"width": width, "bits": bits, "lo": lo.as_dict(), "hi": hi.as_dict()}


def _verify_window(target: int, blob: dict, width: int, ctx: bytes, label: bytes) -> bool:
    if int(blob.get("width", -1)) != width or int(blob.get("bits", -1)) != _bits_for(width):
        return False
    bits = _bits_for(width)
    lo = sg.RangeProof.from_dict(blob["lo"])
    hi = sg.RangeProof.from_dict(blob["hi"])
    if lo.bits != bits or hi.bits != bits:
        return False
    if not sg.verify_range(target, lo, ctx, label + b"|lo"):
        return False
    # complement commitment C2 = g^{width-1} · target^{-1}
    c2 = (sg.g_exp(width - 1) * pow(target, sg.Q - 1, sg.P)) % sg.P
    return sg.verify_range(c2, hi, ctx, label + b"|hi")


# ── prove / verify the fuse relation ─────────────────────────────────────────


def prove_fuse(
    *,
    scale: int,
    fused_q: int,
    streams: list[tuple[str, int, int]],
) -> bytes:
    """Prove ``fused_q == clamp(round(Σ wᵢ·sᵢ / scale))`` for the private scores.

    ``streams`` is the full ordered ``(name, weight, score)`` list (the arbiter's
    seven streams). Only weight>0 streams are committed (a zero-weight stream
    does not enter the fuse). Returns the proof as canonical JSON bytes. Raises
    ``FuseProofError`` if the public ``fused_q`` does not match the private
    scores (the prover refuses to attest a false statement)."""
    half = scale // 2
    contributing = [(n, w, s) for (n, w, s) in streams if w > 0]
    for n, w, s in contributing:
        if not (0 <= s < (1 << SCORE_BITS)):
            raise FuseProofError(f"score for {n} = {s} not in [0,2^{SCORE_BITS})")
        if w < 0:
            raise FuseProofError(f"weight for {n} is negative")

    acc = sum(w * s for _, w, s in contributing)
    fused_unclamped = (acc + half) // scale
    fused_check = min(scale, max(0, fused_unclamped))
    if fused_check != fused_q:
        raise FuseProofError(
            f"public fused_q {fused_q} != fuse of private scores {fused_check}"
        )
    if not (0 <= fused_q <= scale):
        raise FuseProofError(f"fused_q {fused_q} out of [0,{scale}]")

    # commit each contributing score; accumulate the homomorphic randomness.
    rscores = [sg.rand_scalar() for _ in contributing]
    commitments = [sg.commit(s, r) for (_, _, s), r in zip(contributing, rscores)]
    weights_pub = [(n, w) for n, w, _ in contributing]
    ctx = _ctx_bytes(scale, fused_q, weights_pub, commitments)

    streams_blob = []
    for (n, w, s), r, c in zip(contributing, rscores, commitments):
        rp = sg.prove_range(s, r, SCORE_BITS, ctx, b"score|" + n.encode())
        streams_blob.append(
            {"name": n, "weight": w, "commitment": int(c), "range": rp.as_dict()}
        )

    # R_acc is the homomorphic randomness of C_acc = Π Cᵢ^{wᵢ}.
    r_acc = sum(w * r for (_, w, _), r in zip(contributing, rscores)) % sg.Q

    if fused_q == 0:
        # acc < scale - half  (acc ≥ 0 always, so the low clamp never triggers)
        fuse_blob = {"case": "low", "window": _prove_window(acc, r_acc, scale - half, ctx, b"acc")}
    elif fused_q == scale:
        # acc ≥ scale*scale - half ; one-sided lower bound (anything above also
        # clamps to scale). Bit width covers the score-range-bounded max acc.
        t_hi = scale * scale - half
        max_acc = ((1 << SCORE_BITS) - 1) * sum(w for _, w, _ in contributing)
        bits = max(1, (max_acc - t_hi).bit_length()) if max_acc > t_hi else 1
        rp = sg.prove_range(acc - t_hi, r_acc, bits, ctx, b"acc|hi")
        fuse_blob = {"case": "high", "bits": bits, "range": rp.as_dict()}
    else:
        # 0 < fused_q < scale : δ = acc - (fused_q*scale - half) ∈ [0, scale)
        t = fused_q * scale - half
        delta = acc - t
        fuse_blob = {"case": "mid", "window": _prove_window(delta, r_acc, scale, ctx, b"delta")}

    proof = {"scheme": SCHEME, "streams": streams_blob, "fuse": fuse_blob}
    return json.dumps(proof, sort_keys=True, separators=(",", ":")).encode("utf-8")


def verify_fuse(
    *,
    scale: int,
    fused_q: int,
    weights: list[tuple[str, int]],
    proof_bytes: bytes,
) -> bool:
    """Verify a fuse proof against the PUBLIC ``(scale, fused_q, weights)``.

    The private scores are never needed (the hiding property). Returns False on
    any malformation or check failure — never raises. ``weights`` is the full
    ordered seven-stream weight list; the proof must commit exactly the weight>0
    streams (in that order) or verification fails."""
    try:
        proof = json.loads(proof_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return False
    if not isinstance(proof, dict) or proof.get("scheme") != SCHEME:
        return False
    if not (0 <= fused_q <= scale) or scale <= 0:
        return False

    half = scale // 2
    expected = [(n, w) for n, w in weights if w > 0]
    streams = proof.get("streams")
    fuse = proof.get("fuse")
    if not isinstance(streams, list) or not isinstance(fuse, dict):
        return False
    if len(streams) != len(expected):
        return False

    commitments: list[int] = []
    weights_pub: list[tuple[str, int]] = []
    try:
        for blob, (en, ew) in zip(streams, expected):
            if blob.get("name") != en or int(blob.get("weight")) != ew:
                return False
            if ew < 0:
                return False
            commitments.append(int(blob["commitment"]))
            weights_pub.append((en, ew))
    except (KeyError, TypeError, ValueError):
        return False

    ctx = _ctx_bytes(scale, fused_q, weights_pub, commitments)

    # per-score range proofs, and the homomorphic accumulator C_acc.
    c_acc = 1
    try:
        for blob, c, (n, w) in zip(streams, commitments, weights_pub):
            rp = sg.RangeProof.from_dict(blob["range"])
            if rp.bits != SCORE_BITS:
                return False
            if not sg.verify_range(c, rp, ctx, b"score|" + n.encode()):
                return False
            c_acc = (c_acc * pow(c, w, sg.P)) % sg.P
    except (KeyError, TypeError, ValueError):
        return False

    case = fuse.get("case")
    try:
        if case == "low":
            if fused_q != 0:
                return False
            return _verify_window(c_acc, fuse["window"], scale - half, ctx, b"acc")
        if case == "high":
            if fused_q != scale:
                return False
            t_hi = scale * scale - half
            max_acc = ((1 << SCORE_BITS) - 1) * sum(w for _, w in weights_pub)
            bits = max(1, (max_acc - t_hi).bit_length()) if max_acc > t_hi else 1
            if int(fuse.get("bits", -1)) != bits:
                return False
            rp = sg.RangeProof.from_dict(fuse["range"])
            if rp.bits != bits:
                return False
            target = (c_acc * pow(sg.g_exp(t_hi), sg.Q - 1, sg.P)) % sg.P
            return sg.verify_range(target, rp, ctx, b"acc|hi")
        if case == "mid":
            if not (0 < fused_q < scale):
                return False
            t = fused_q * scale - half
            target = (c_acc * pow(sg.g_exp(t), sg.Q - 1, sg.P)) % sg.P
            return _verify_window(target, fuse["window"], scale, ctx, b"delta")
    except (KeyError, TypeError, ValueError):
        return False
    return False


__all__ = ["SCHEME", "SCORE_BITS", "FuseProofError", "prove_fuse", "verify_fuse"]
