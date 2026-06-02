"""
Verifiable index-hiding batch sampler — VFT element 2.

What this implements
--------------------
VFT (arxiv 2510.16830 §III.B) identifies *batch sampling* as the
hardest-to-audit element of a fine-tuning run. The released model
must be obtainable from a *specific* sequence of batches; if the
batches are public, the prover can leak which records were used in
which step (de-anonymizes the dataset). If the batches are private,
the prover can claim any batch sequence that happens to be
consistent with the released model.

VFT resolves this with two modes that share the same circuit:

1. **Public replayable sampling** — the prover discloses the seed,
   a verifier rederives the exact batch sequence, the proof shows
   the model evolved under that sequence.
2. **Private index-hiding sampling** — the prover commits to the
   seed once, derives the batches, and proves consistency without
   revealing the seed. The verifier learns *that* a valid seed
   exists, not which records were touched at which step.

Both modes use the same PRF construction so the circuit is the
same in both cases; the only difference is whether the seed is in
the public input or the witness.

PRF choice
----------
SHAKE128 is the chosen sampler PRF here. ChaCha20 is a defensible
alternative; the spec is silent on the PRF as long as the prover
and verifier agree, and SHAKE128 is already a wired dependency via
the FIPS-204 ML-DSA hash internals. Using SHAKE keeps the symmetric
side of the PQ posture aligned (no SHA-2 chains under PRF stress).

Implementation notes
--------------------
* Pure stdlib + ``cryptography``. No FFI.
* Deterministic across machines (no platform-dependent floats or
  randomness).
* The sampler is *not* a Halo2 circuit; it's the Python side that
  generates the witness. The corresponding in-circuit PRF lives
  in the bundled ezkl circuit description (out-of-band artifact;
  see ``tex.zkprov.backends.Halo2IpaBackend``).
"""

from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass
from enum import Enum


class SamplerMode(str, Enum):
    """How the sampler binds the seed.

    - ``PUBLIC_REPLAYABLE``: seed is on the proof statement; anyone
      can rederive the exact batch sequence.
    - ``PRIVATE_INDEX_HIDING``: only ``seed_commitment`` is on the
      statement; ``seed`` itself is in the witness.
    """

    PUBLIC_REPLAYABLE = "public-replayable"
    PRIVATE_INDEX_HIDING = "private-index-hiding"


@dataclass(frozen=True, slots=True)
class BatchSchedule:
    """A deterministic batch sequence derived from ``seed``.

    Each entry is a tuple of record indices for one optimizer step.
    """

    epoch: int
    steps: tuple[tuple[int, ...], ...]


@dataclass(frozen=True, slots=True)
class SamplerCommitment:
    """What the prover puts on the proof statement.

    For PUBLIC_REPLAYABLE: ``seed`` is set, ``seed_commitment`` is
    derived. For PRIVATE_INDEX_HIDING: ``seed`` is None,
    ``seed_commitment`` is on the statement, and the prover keeps
    ``seed`` in the witness.
    """

    mode: SamplerMode
    seed_commitment: str  # 64-char hex (SHA-256 of (domain || seed))
    record_count: int
    batch_size: int
    steps_per_epoch: int
    total_epochs: int

    # Only populated for PUBLIC_REPLAYABLE.
    seed_hex: str | None = None


_PRF_DOMAIN = b"tex/zkprov/sampler-v1\x00"


def commit_seed(seed: bytes) -> str:
    """Public commitment to a sampler seed."""
    h = hashlib.sha256()
    h.update(_PRF_DOMAIN)
    h.update(b"\x01commit\x00")
    h.update(seed)
    return h.hexdigest()


def derive_batch_schedule(
    *,
    seed: bytes,
    record_count: int,
    batch_size: int,
    steps_per_epoch: int,
    epoch: int,
) -> BatchSchedule:
    """Derive a batch schedule for one epoch deterministically.

    The PRF is ``SHAKE128(domain || "schedule" || seed || u32(epoch))``.
    SHAKE128 supports arbitrary-length output, so the schedule is
    materialized by streaming bytes and reducing each chunk modulo
    ``record_count``.

    Determinism guarantees:
      * Same (seed, record_count, batch_size, steps_per_epoch, epoch)
        -> same schedule, byte-for-byte, on any machine.
      * Different epochs -> independent schedules.

    Bias note:
      Reducing 4 random bytes modulo a non-power-of-two
      record_count introduces a tiny modular bias. For the audit
      use-case here (records counted in the thousands to millions),
      the bias is far below regulatory significance. A bias-free
      rejection sampler is on the backlog and switching the
      ``circuit_version`` field is the migration path.
    """
    if record_count <= 0 or batch_size <= 0 or steps_per_epoch <= 0:
        raise ValueError("record_count, batch_size, steps_per_epoch must be positive")
    if batch_size > record_count:
        raise ValueError("batch_size cannot exceed record_count")

    bytes_per_index = 4  # 32-bit reductions
    bytes_per_step = batch_size * bytes_per_index
    total_bytes = steps_per_epoch * bytes_per_step

    shake = hashlib.shake_128()
    shake.update(_PRF_DOMAIN)
    shake.update(b"\x02schedule\x00")
    shake.update(seed)
    shake.update(epoch.to_bytes(4, "big"))
    stream = shake.digest(total_bytes)

    steps: list[tuple[int, ...]] = []
    cursor = 0
    for _ in range(steps_per_epoch):
        indices: list[int] = []
        for _ in range(batch_size):
            raw = int.from_bytes(stream[cursor : cursor + 4], "big")
            indices.append(raw % record_count)
            cursor += 4
        steps.append(tuple(indices))

    return BatchSchedule(epoch=epoch, steps=tuple(steps))


def commit_schedule(schedule: BatchSchedule) -> str:
    """Content hash over a derived schedule.

    Carried on the proof statement when the circuit needs to bind
    the materialized schedule (as opposed to just the seed). For
    PRIVATE_INDEX_HIDING this is the *expected* schedule commitment
    that the circuit recomputes from the witnessed seed.
    """
    h = hashlib.sha256()
    h.update(_PRF_DOMAIN)
    h.update(b"\x03schedhash\x00")
    h.update(schedule.epoch.to_bytes(4, "big"))
    h.update(len(schedule.steps).to_bytes(4, "big"))
    for step in schedule.steps:
        h.update(len(step).to_bytes(4, "big"))
        for idx in step:
            h.update(idx.to_bytes(4, "big"))
    return h.hexdigest()


def make_sampler_commitment(
    *,
    mode: SamplerMode,
    seed: bytes | None,
    record_count: int,
    batch_size: int,
    steps_per_epoch: int,
    total_epochs: int,
) -> SamplerCommitment:
    """Build the on-statement sampler commitment.

    For PUBLIC_REPLAYABLE, ``seed`` must be provided. For
    PRIVATE_INDEX_HIDING, ``seed`` may be provided (it then becomes
    part of the witness) or omitted (and a fresh CSPRNG seed is
    chosen and kept by the caller for the witness).
    """
    if mode is SamplerMode.PUBLIC_REPLAYABLE:
        if seed is None:
            raise ValueError("PUBLIC_REPLAYABLE requires a seed")
        seed_commitment = commit_seed(seed)
        return SamplerCommitment(
            mode=mode,
            seed_commitment=seed_commitment,
            record_count=record_count,
            batch_size=batch_size,
            steps_per_epoch=steps_per_epoch,
            total_epochs=total_epochs,
            seed_hex=seed.hex(),
        )

    # PRIVATE_INDEX_HIDING
    if seed is None:
        seed = secrets.token_bytes(32)
    seed_commitment = commit_seed(seed)
    return SamplerCommitment(
        mode=mode,
        seed_commitment=seed_commitment,
        record_count=record_count,
        batch_size=batch_size,
        steps_per_epoch=steps_per_epoch,
        total_epochs=total_epochs,
        seed_hex=None,  # withheld in private mode
    )


def replay_public_sampler(
    commitment: SamplerCommitment,
    *,
    epoch: int,
) -> BatchSchedule:
    """Verifier-side replay of a PUBLIC_REPLAYABLE sampler.

    For PRIVATE_INDEX_HIDING the verifier cannot reproduce the
    schedule (that's the whole point); use the in-circuit
    consistency check instead.
    """
    if commitment.mode is not SamplerMode.PUBLIC_REPLAYABLE:
        raise ValueError("replay is only valid for PUBLIC_REPLAYABLE samplers")
    if commitment.seed_hex is None:
        raise ValueError("PUBLIC_REPLAYABLE sampler has no seed")
    seed = bytes.fromhex(commitment.seed_hex)
    if commit_seed(seed) != commitment.seed_commitment:
        raise ValueError("seed does not match seed_commitment")
    return derive_batch_schedule(
        seed=seed,
        record_count=commitment.record_count,
        batch_size=commitment.batch_size,
        steps_per_epoch=commitment.steps_per_epoch,
        epoch=epoch,
    )


__all__ = [
    "SamplerMode",
    "BatchSchedule",
    "SamplerCommitment",
    "commit_seed",
    "derive_batch_schedule",
    "commit_schedule",
    "make_sampler_commitment",
    "replay_public_sampler",
]
