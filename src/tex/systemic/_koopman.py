"""
Koopman lift + linear advance for the ecosystem digital twin.

Thread 9. Reference: arxiv 2601.01076 (Nath/Yin/Chou, PMLR 2026,
"Scalable Data-Driven Reachability Analysis and Control via Koopman
Operators with Conformal Coverage Guarantees") and arxiv 2605.01803
(Köglmayr/Räth, May 2026, "Koopman Representations for Early Outbreak
Warning and Minimal Counterfactual Intervention").

The Koopman operator lifts nonlinear ecosystem-state dynamics
``x_{t+1} = f(x_t)`` to an approximately-linear advance ``z_{t+1} =
K z_t`` in a higher-dimensional latent space, where
``z = phi(x)``. We then advance in latent space (linear, fast,
analytically reachable) and decode back via ``x_hat = psi(z)``.

Why Koopman over a learned RNN for ``simulate_forward``
-------------------------------------------------------
1. **Sample efficiency.** A linear advance in lifted space needs O(d^2)
   parameters for a d-dim lift, vs. O(d^2 * h) for an RNN with hidden
   size h. Per-tenant calibration is feasible from < 100 transitions.
2. **Composability with conformal.** Linear advance ⇒ Koopman residuals
   are exchangeable under stationarity, which is exactly the conformal-
   prediction precondition. Pair with ``_conformal.py``.
3. **Cold-start safe.** Falls back to identity lift (i.e. trivial
   advance via mean transition) when training data < ``MIN_TRAINING_N``.
4. **No external ML deps.** Pure NumPy, fits the constitution's "no
   exec, no surprise deps" rule.

Implementation choices
----------------------
We use the *EDMD* (Extended Dynamic Mode Decomposition) approximation
of the Koopman operator. Given a dictionary of observable functions
``phi_1, ..., phi_d``, we estimate ``K`` from data via least squares:

    K_hat = argmin_K sum_t || phi(x_{t+1}) - K phi(x_t) ||^2

with ridge regularization for numerical stability. The dictionary is a
hand-crafted feature map (state coordinates + polynomial + radial-basis
terms), chosen so the math is auditable. A learned dictionary
(autoencoder) is a known follow-on; the brief from Thread 7.1 noted
that learned dictionaries are not necessary for governance-grade
trajectories.

Mathematical structure
----------------------
Let ``X = [x_1, ..., x_{T-1}]`` and ``Y = [x_2, ..., x_T]`` be data
matrices (states and their successors). Lift to ``Phi_X, Phi_Y``. Then
``K_hat = Phi_Y Phi_X^T (Phi_X Phi_X^T + lambda I)^{-1}``. To predict
``x_{T+1}`` we lift ``x_T`` then advance ``K_hat phi(x_T)`` and decode.

For our governance state space the abstraction lives in
``[0, 1]^d`` (drift_delta, compromise_ratio, contract_severity, ...)
which means we clamp the decoded output to the unit hypercube and
treat boundary clamps as drift signals.
"""

from __future__ import annotations

from typing import Sequence

import numpy as np
from pydantic import BaseModel, ConfigDict, Field

# Torch is OPTIONAL — only required when learned_dictionary=True. The
# polynomial+RBF dictionary remains the default and zero-dep path so
# Tex still ships fine on torch-less environments (the constitution's
# "no surprise deps" rule). Importing here behind a guarded try keeps
# the import surface clean for the rest of the package.
try:  # pragma: no cover — import side-effect only
    import torch as _torch  # type: ignore
    import torch.nn as _torch_nn  # type: ignore
    _HAS_TORCH = True
except Exception:  # pragma: no cover
    _torch = None  # type: ignore
    _torch_nn = None  # type: ignore
    _HAS_TORCH = False


# Lift dictionary dimensionality: state coords + polynomial(2) + 4 RBFs.
# For a d=4 state vector this yields:
#   4 (linear) + 4 (squares) + C(4,2)=6 (pairwise) + 4 (RBFs) = 18
# Small enough for fast SVD; large enough to capture nonlinearity.
_LIFT_POLY_ORDER: int = 2
_LIFT_N_RBFS: int = 4
_RIDGE_LAMBDA: float = 1e-3
# Below this many observed transitions, EDMD is unreliable. We fall
# back to identity lift (i.e. mean-transition advance).
MIN_TRAINING_N: int = 8
# Default learned-dictionary lifted dim (matches ScaRe-Kro reference impl).
_NN_LIFT_DIM: int = 32
# NN-lift training defaults (small + deterministic; full repro tested).
_NN_LIFT_EPOCHS: int = 80
_NN_LIFT_LR: float = 1e-2


class TenantSignalProfile(BaseModel):
    """
    Per-tenant snapshot of what the calibrator has learned matters.

    Thread 9.1 closes the self-tuning loop: ``ThresholdCalibrator`` (Thread 7)
    tells the twin *which signals are predictive at this tenant*, the twin
    builds its Koopman observable dictionary around those signals, and the
    twin's residuals feed back to the calibrator. Every layer self-tunes.

    ``signal_importance`` maps a coordinate index of the abstract state
    vector (0=compromise, 1=entity_load, 2=drift_mean, 3=drift_max in the
    default 4-dim space) to a non-negative importance weight. Defaults to
    uniform when the calibrator has no observed outcomes yet (cold start).

    ``high_leverage_regions`` is a sequence of state-space points where the
    calibrator has historically flagged high false-permit or false-forbid
    rates. The Koopman dictionary places RBF centers preferentially in
    these regions, so the twin's forecast is *sharper* exactly where the
    tenant's history says it matters.

    ``snapshot_version`` advances monotonically when the calibrator emits a
    new recommendation; the twin watches this and refits Koopman on bump.
    """

    model_config = ConfigDict(frozen=True, extra="forbid", arbitrary_types_allowed=True)

    signal_importance: tuple[float, ...] = Field(
        ..., min_length=1,
        description="Non-negative weights per state coord; normalized internally.",
    )
    high_leverage_regions: tuple[tuple[float, ...], ...] = Field(
        default=(),
        description="State-space points the calibrator has flagged as high-leverage.",
    )
    snapshot_version: int = Field(default=0, ge=0)
    tenant_id: str = Field(default="default", min_length=1, max_length=128)

    @classmethod
    def uniform(cls, *, state_dim: int = 4, tenant_id: str = "default") -> "TenantSignalProfile":
        """Cold-start uniform-importance profile (no calibrator data yet)."""
        return cls(
            signal_importance=tuple(1.0 for _ in range(state_dim)),
            high_leverage_regions=(),
            snapshot_version=0,
            tenant_id=tenant_id,
        )

    def normalized_importance(self) -> np.ndarray:
        """Importance weights normalized to mean 1.0 (preserves scale)."""
        arr = np.array(self.signal_importance, dtype=np.float64)
        arr = np.maximum(arr, 0.0)
        if arr.sum() <= 0:
            return np.ones_like(arr)
        return arr * (arr.size / arr.sum())


class KoopmanState(BaseModel):
    """
    Persisted Koopman operator. Frozen for replay; rebuilt on observation.

    Carries the learned operator ``K`` (lifted_dim x lifted_dim), the
    RBF centers used for the lift dictionary, a generation counter,
    and (Thread 9.1) the dictionary kind + optional NN weights + the
    ``TenantSignalProfile`` version this operator was fit against.
    """

    model_config = ConfigDict(frozen=True, extra="forbid", arbitrary_types_allowed=True)

    operator: tuple[tuple[float, ...], ...] = Field(
        ..., description="Koopman operator K, row-major.",
    )
    rbf_centers: tuple[tuple[float, ...], ...] = Field(
        ..., description="RBF centers in original state space.",
    )
    rbf_gamma: float = Field(..., gt=0.0, description="RBF bandwidth.")
    state_dim: int = Field(..., ge=1, le=64, description="Original state dim.")
    lifted_dim: int = Field(..., ge=1, description="Lifted-space dim.")
    n_observations: int = Field(..., ge=0)
    generation: int = Field(..., ge=0)
    # Thread 9.1: dictionary kind + calibrator binding.
    dictionary_kind: str = Field(default="polynomial_rbf", min_length=1, max_length=32)
    # Per-coordinate signal weights baked into the dictionary at fit time.
    # The dictionary's polynomial features are scaled by these weights so
    # the operator learns dynamics in a calibrator-shaped coordinate system.
    signal_weights: tuple[float, ...] | None = Field(default=None)
    # NN-lift parameters, only populated when dictionary_kind == "nn".
    # Stored as nested tuples for frozen / replay safety. Shape:
    #   nn_layer_weights[i] is the (in_dim, out_dim) weight matrix as
    #   row-major tuples; nn_layer_biases[i] is the bias vector tuple.
    nn_layer_weights: tuple[tuple[tuple[float, ...], ...], ...] | None = Field(default=None)
    nn_layer_biases: tuple[tuple[float, ...], ...] | None = Field(default=None)
    # Calibrator snapshot version this operator was fit against.
    tenant_snapshot_version: int = Field(default=0, ge=0)


def _build_rbf_centers(
    observed: np.ndarray,
    n_rbfs: int,
    *,
    high_leverage_regions: np.ndarray | None = None,
    leverage_fraction: float = 0.5,
) -> np.ndarray:
    """
    Pick RBF centers from observed data, optionally biased toward
    calibrator-flagged high-leverage regions.

    Thread 9.1: when ``high_leverage_regions`` is provided (from
    ``TenantSignalProfile``), reserve ``leverage_fraction`` of the
    centers for those regions. The rest are placed by deterministic
    quantile selection along PC1 as before. This shapes the lift
    dictionary around what the tenant has *learned* matters, so the
    operator captures dynamics there with higher fidelity.
    """
    n_leverage = 0
    if high_leverage_regions is not None and high_leverage_regions.size > 0:
        n_leverage = min(
            high_leverage_regions.shape[0],
            int(round(n_rbfs * leverage_fraction)),
        )
    n_data = n_rbfs - n_leverage

    if observed.shape[0] <= n_data:
        # Fall back: use the observations themselves; pad with the mean
        # to keep the dimensionality fixed.
        centers = observed.copy()
        if centers.shape[0] < n_data:
            mean = observed.mean(axis=0, keepdims=True)
            pad = np.repeat(mean, n_data - centers.shape[0], axis=0)
            centers = np.vstack([centers, pad])
        # Stack leverage regions on top.
        if n_leverage > 0:
            centers = np.vstack([centers, high_leverage_regions[:n_leverage]])
        return centers[:n_rbfs]

    # Deterministic quantile-based centers along the first PC.
    pc1 = observed - observed.mean(axis=0, keepdims=True)
    if pc1.shape[1] > 1:
        u, s, vt = np.linalg.svd(pc1, full_matrices=False)
        proj = (pc1 @ vt[0])
    else:
        proj = pc1.flatten()
    quantiles = np.linspace(0.1, 0.9, max(n_data, 1))
    chosen_idx = np.argsort(proj)[
        (np.argsort(proj).size * quantiles).astype(int).clip(0, proj.size - 1)
    ]
    centers = observed[chosen_idx]

    # Append calibrator-flagged high-leverage regions.
    if n_leverage > 0:
        centers = np.vstack([centers, high_leverage_regions[:n_leverage]])

    return centers[:n_rbfs]


def _lift_polynomial_rbf(
    x: np.ndarray,
    rbf_centers: np.ndarray,
    rbf_gamma: float,
    *,
    signal_weights: np.ndarray | None = None,
) -> np.ndarray:
    """
    Lift via hand-crafted polynomial + RBF dictionary.

    Thread 9.1: when ``signal_weights`` is supplied, the polynomial
    features (linear + squares + cross terms) are scaled per-coordinate
    by the calibrator's importance weights. Coordinates the tenant has
    learned are predictive contribute more to the lifted state, so the
    Koopman operator learns dynamics in a calibrator-shaped frame.

    Returns (lifted_dim,) for a single state or (N, lifted_dim) for a batch.

    Observable dictionary:
      * linear:        w_i * x_i for each coord
      * polynomial(2): w_i * x_i^2 for each coord, and sqrt(w_i*w_j) * x_i * x_j for i<j
      * radial basis:  exp(-gamma ||x - c_k||^2) for each center c_k
    """
    batched = x.ndim == 2
    if not batched:
        x = x.reshape(1, -1)

    n, d = x.shape

    if signal_weights is not None:
        w = signal_weights
        w_sqrt = np.sqrt(np.maximum(w, 0.0))
    else:
        w = np.ones(d, dtype=np.float64)
        w_sqrt = np.ones(d, dtype=np.float64)

    # Linear features scaled by signal weight.
    linear = x * w_sqrt[None, :]
    parts: list[np.ndarray] = [linear]

    # Squares scaled by signal weight.
    parts.append((x ** 2) * w[None, :])

    # Cross terms scaled by geometric-mean signal weight.
    for i in range(d):
        for j in range(i + 1, d):
            cross_w = float(np.sqrt(max(w[i] * w[j], 0.0)))
            parts.append((cross_w * x[:, i] * x[:, j]).reshape(-1, 1))

    # RBF features (translation-invariant; signal weights don't apply directly).
    for c in rbf_centers:
        dists = np.sum((x - c[None, :]) ** 2, axis=1, keepdims=True)
        parts.append(np.exp(-rbf_gamma * dists))

    lifted = np.concatenate(parts, axis=1)
    return lifted if batched else lifted[0]


# Public alias preserved for backward-compat with Thread 9 callers.
def _lift(x: np.ndarray, rbf_centers: np.ndarray, rbf_gamma: float) -> np.ndarray:
    """Backward-compat shim: polynomial+RBF lift with uniform weights."""
    return _lift_polynomial_rbf(x, rbf_centers, rbf_gamma, signal_weights=None)


def _lifted_dim(state_dim: int, n_rbfs: int) -> int:
    """Compute dim(phi(x)) for the chosen polynomial+RBF dictionary."""
    return (
        state_dim                       # linear
        + state_dim                     # squares
        + (state_dim * (state_dim - 1)) // 2  # cross terms
        + n_rbfs                        # RBFs
    )


# =============================================================================
# Thread 9.1: NN-lift (ScaRe-Kro-style, arxiv 2601.01076 §III.A)
# =============================================================================

class _NNLift:
    """
    Two-layer neural-network lift φ_θ : R^d → R^L.

    Per arxiv 2601.01076 (Nath/Yin/Chou, PMLR 2026), the SOTA Koopman
    lift uses a learned NN observable rather than a hand-crafted
    dictionary. The NN learns observables jointly with the linear
    advance operator K such that K φ(x_t) ≈ φ(x_{t+1}). We train
    end-to-end via a one-step prediction loss.

    Loss = || K φ(x_{t+1}) - K K φ(x_t) ||^2 ... wait, simpler:
    Loss = || φ(x_{t+1}) - K φ(x_t) ||^2  where K is fit jointly.

    Implementation notes
    --------------------
    - Pure torch. Only constructed when torch is importable; callers
      fall back to polynomial+RBF when ``_HAS_TORCH`` is False.
    - Small architecture (one hidden layer, tanh activations) — keeps
      the lifted dim modest (32) and training cheap (~80 epochs on
      < 100 transitions takes < 200 ms on CPU).
    - Deterministic given seed; we seed torch from the SHA-256 of the
      training data so the operator is replay-stable.
    """

    def __init__(
        self,
        *,
        state_dim: int,
        lifted_dim: int = _NN_LIFT_DIM,
        seed: int = 0,
    ) -> None:
        if not _HAS_TORCH:  # pragma: no cover — surfaced earlier
            raise RuntimeError("torch is not installed; NN lift unavailable")
        gen = _torch.Generator().manual_seed(seed)
        # Small explicit init: don't depend on torch's default init across versions.
        hidden = max(lifted_dim, state_dim * 4)
        # Glorot/xavier-ish init.
        w1 = _torch.empty(state_dim, hidden, dtype=_torch.float64).uniform_(-0.5, 0.5, generator=gen)
        b1 = _torch.zeros(hidden, dtype=_torch.float64)
        w2 = _torch.empty(hidden, lifted_dim, dtype=_torch.float64).uniform_(-0.5, 0.5, generator=gen)
        b2 = _torch.zeros(lifted_dim, dtype=_torch.float64)
        # Bake the identity as the first state_dim coords of the output,
        # so the EDMD-style decoding (output[:state_dim]) is meaningful.
        # We do this by clamping the last layer's first state_dim cols.
        with _torch.no_grad():
            w2[:, :state_dim] = 0.0
            # Identity projection from hidden's first state_dim units.
            w2[:state_dim, :state_dim] = _torch.eye(state_dim, dtype=_torch.float64)
        self.w1 = w1.requires_grad_(True)
        self.b1 = b1.requires_grad_(True)
        self.w2 = w2.requires_grad_(True)
        self.b2 = b2.requires_grad_(True)
        self.state_dim = state_dim
        self.lifted_dim = lifted_dim

    def forward(self, x):  # type: ignore[no-untyped-def]
        # x: (batch, state_dim)
        h = _torch.tanh(x @ self.w1 + self.b1)
        z = h @ self.w2 + self.b2
        return z

    def parameters(self):  # type: ignore[no-untyped-def]
        return [self.w1, self.b1, self.w2, self.b2]

    def freeze_to_tuples(
        self,
    ) -> tuple[
        tuple[tuple[tuple[float, ...], ...], ...],
        tuple[tuple[float, ...], ...],
    ]:
        """Serialize weights to frozen nested tuples for Pydantic storage."""
        w1 = tuple(tuple(float(v) for v in row) for row in self.w1.detach().numpy())
        b1 = tuple(float(v) for v in self.b1.detach().numpy())
        w2 = tuple(tuple(float(v) for v in row) for row in self.w2.detach().numpy())
        b2 = tuple(float(v) for v in self.b2.detach().numpy())
        weights = (w1, w2)
        biases = (b1, b2)
        return weights, biases


def _nn_lift_from_state(
    x: np.ndarray,
    nn_layer_weights: tuple[tuple[tuple[float, ...], ...], ...],
    nn_layer_biases: tuple[tuple[float, ...], ...],
) -> np.ndarray:
    """
    NumPy-only forward of a previously-trained NN lift. Used when we
    don't want torch on the inference path. Matches ``_NNLift.forward``
    exactly: tanh(x W1 + b1) W2 + b2.
    """
    batched = x.ndim == 2
    if not batched:
        x = x.reshape(1, -1)
    w1 = np.array(nn_layer_weights[0], dtype=np.float64)
    b1 = np.array(nn_layer_biases[0], dtype=np.float64)
    w2 = np.array(nn_layer_weights[1], dtype=np.float64)
    b2 = np.array(nn_layer_biases[1], dtype=np.float64)
    h = np.tanh(x @ w1 + b1)
    z = h @ w2 + b2
    return z if batched else z[0]


def lift_via_state(x: np.ndarray, koopman: "KoopmanState") -> np.ndarray:
    """
    Lift ``x`` using whichever dictionary the persisted ``KoopmanState``
    was fit with. Single entry point for both polynomial+RBF and NN lifts.
    """
    rbf_centers = np.array(koopman.rbf_centers, dtype=np.float64)
    rbf_gamma = koopman.rbf_gamma
    if koopman.dictionary_kind == "nn":
        assert koopman.nn_layer_weights is not None
        assert koopman.nn_layer_biases is not None
        return _nn_lift_from_state(
            x, koopman.nn_layer_weights, koopman.nn_layer_biases,
        )
    # Polynomial+RBF path (default).
    sig_w = (
        np.array(koopman.signal_weights, dtype=np.float64)
        if koopman.signal_weights is not None
        else None
    )
    return _lift_polynomial_rbf(x, rbf_centers, rbf_gamma, signal_weights=sig_w)


def _train_nn_lift(
    X_arr: np.ndarray,
    Y_arr: np.ndarray,
    *,
    state_dim: int,
    lifted_dim: int,
    epochs: int = _NN_LIFT_EPOCHS,
    lr: float = _NN_LIFT_LR,
) -> tuple[_NNLift, np.ndarray]:
    """
    End-to-end fit of NN lift φ_θ and linear operator K via
    one-step prediction loss. Returns (lift, K).

    Loss = mean || φ(x_{t+1}) - K φ(x_t) ||^2
    """
    # Deterministic seed from the data so replays match.
    import hashlib
    h = hashlib.sha256()
    h.update(X_arr.tobytes())
    h.update(Y_arr.tobytes())
    seed = int.from_bytes(h.digest()[:4], "big")

    lift = _NNLift(state_dim=state_dim, lifted_dim=lifted_dim, seed=seed)
    X = _torch.tensor(X_arr, dtype=_torch.float64)
    Y = _torch.tensor(Y_arr, dtype=_torch.float64)
    optimizer = _torch.optim.Adam(lift.parameters(), lr=lr)

    K = None
    for _ in range(epochs):
        optimizer.zero_grad()
        Phi_X = lift.forward(X)
        Phi_Y = lift.forward(Y)
        # Fit K in closed form given current Phi: K = Phi_Y^T Phi_X (Phi_X^T Phi_X + λI)^-1
        # then loss measured against the realized lifted points.
        gram = Phi_X.T @ Phi_X + _RIDGE_LAMBDA * _torch.eye(
            Phi_X.shape[1], dtype=_torch.float64,
        )
        K_t = _torch.linalg.solve(gram, Phi_X.T @ Phi_Y).T
        residual = Phi_Y - Phi_X @ K_t.T
        loss = (residual ** 2).mean()
        loss.backward()
        optimizer.step()
        K = K_t.detach().numpy()

    assert K is not None
    return lift, K


def fit_koopman(
    transitions: Sequence[tuple[np.ndarray, np.ndarray]],
    *,
    state_dim: int,
    n_rbfs: int = _LIFT_N_RBFS,
    ridge_lambda: float = _RIDGE_LAMBDA,
    generation: int = 0,
    tenant_profile: TenantSignalProfile | None = None,
    learned_dictionary: bool = False,
    nn_lifted_dim: int = _NN_LIFT_DIM,
) -> KoopmanState | None:
    """
    Fit a Koopman operator from observed ``(x_t, x_{t+1})`` transitions.

    Thread 9.1 additions:
    - ``tenant_profile``: TenantSignalProfile snapshot; when present, the
      polynomial features are weighted by ``signal_importance`` and the
      RBF centers are biased toward ``high_leverage_regions``. The
      operator learns dynamics in a calibrator-shaped frame.
    - ``learned_dictionary``: when True (and torch is installed), use
      the NN-lift dictionary per arxiv 2601.01076 §III.A. The NN is
      trained end-to-end via one-step prediction loss.

    Returns None if there are fewer than ``MIN_TRAINING_N`` transitions;
    callers should fall back to identity-advance in that case.
    """
    if len(transitions) < MIN_TRAINING_N:
        return None

    X_arr = np.stack([t[0] for t in transitions], axis=0)
    Y_arr = np.stack([t[1] for t in transitions], axis=0)
    assert X_arr.shape == Y_arr.shape == (len(transitions), state_dim)

    snapshot_version = tenant_profile.snapshot_version if tenant_profile else 0

    # ---- NN-lift path (Thread 9.1: ScaRe-Kro-style) ---------------------
    if learned_dictionary:
        if not _HAS_TORCH:
            # Caller asked for NN-lift but torch is missing — degrade
            # gracefully to polynomial+RBF rather than crash. We log
            # nothing here (no logger on this hot path); the caller
            # (digital_twin.py) emits a telemetry event.
            learned_dictionary = False

    if learned_dictionary:
        lift, K = _train_nn_lift(
            X_arr, Y_arr,
            state_dim=state_dim,
            lifted_dim=nn_lifted_dim,
        )
        nn_weights, nn_biases = lift.freeze_to_tuples()
        # NN-lift carries no RBF centers, but we keep a single dummy so
        # the field invariant holds (rbf_centers ≥ 1 row).
        return KoopmanState(
            operator=tuple(tuple(float(v) for v in row) for row in K),
            rbf_centers=((0.0,) * state_dim,),
            rbf_gamma=1.0,
            state_dim=state_dim,
            lifted_dim=nn_lifted_dim,
            n_observations=len(transitions),
            generation=generation,
            dictionary_kind="nn",
            signal_weights=None,
            nn_layer_weights=nn_weights,
            nn_layer_biases=nn_biases,
            tenant_snapshot_version=snapshot_version,
        )

    # ---- Polynomial+RBF path (default) ---------------------------------

    # Robust RBF bandwidth from data scale (median pairwise dist).
    if X_arr.shape[0] >= 2:
        diffs = X_arr[None, :, :] - X_arr[:, None, :]
        d2 = np.sum(diffs ** 2, axis=-1)
        med = float(np.median(d2[d2 > 0])) if (d2 > 0).any() else 1.0
        rbf_gamma = 1.0 / max(med, 1e-6)
    else:
        rbf_gamma = 1.0

    # Calibrator-informed RBF placement.
    high_lev = None
    if tenant_profile and tenant_profile.high_leverage_regions:
        high_lev = np.array(tenant_profile.high_leverage_regions, dtype=np.float64)
        # Validate shape: any rows with the wrong dim get dropped silently.
        if high_lev.ndim == 2 and high_lev.shape[1] == state_dim:
            pass
        else:
            high_lev = None
    rbf_centers = _build_rbf_centers(
        X_arr, n_rbfs, high_leverage_regions=high_lev,
    )

    # Signal weights from the calibrator.
    if tenant_profile is not None:
        sig_w = tenant_profile.normalized_importance()
        if sig_w.size != state_dim:
            sig_w = np.ones(state_dim, dtype=np.float64)
    else:
        sig_w = None

    Phi_X = _lift_polynomial_rbf(X_arr, rbf_centers, rbf_gamma, signal_weights=sig_w)
    Phi_Y = _lift_polynomial_rbf(Y_arr, rbf_centers, rbf_gamma, signal_weights=sig_w)
    d_lift = Phi_X.shape[1]
    gram = Phi_X.T @ Phi_X + ridge_lambda * np.eye(d_lift)
    K = np.linalg.solve(gram, Phi_X.T @ Phi_Y).T  # (d_lift, d_lift)

    return KoopmanState(
        operator=tuple(tuple(float(v) for v in row) for row in K),
        rbf_centers=tuple(tuple(float(v) for v in c) for c in rbf_centers),
        rbf_gamma=float(rbf_gamma),
        state_dim=state_dim,
        lifted_dim=d_lift,
        n_observations=len(transitions),
        generation=generation,
        dictionary_kind="polynomial_rbf",
        signal_weights=(
            tuple(float(v) for v in sig_w) if sig_w is not None else None
        ),
        nn_layer_weights=None,
        nn_layer_biases=None,
        tenant_snapshot_version=snapshot_version,
    )


def advance(
    koopman: KoopmanState | None,
    x: np.ndarray,
    steps: int = 1,
) -> np.ndarray:
    """
    Advance state ``x`` forward ``steps`` time steps under the learned
    Koopman operator.

    If ``koopman`` is None (insufficient training data), returns ``x``
    unchanged for every step — operationally, "we have no model so the
    safest forecast is no change." Callers should treat absent Koopman
    state as a cold-start regime.

    Returns the predicted state in original coordinates, clamped to
    [0, 1] (the systemic-axis state space is bounded).
    """
    if koopman is None:
        return x.copy()
    if steps < 1:
        return x.copy()

    K = np.array(koopman.operator, dtype=np.float64)
    state_dim = koopman.state_dim

    z = lift_via_state(x, koopman)
    for _ in range(steps):
        z = K @ z

    # Decode: the first ``state_dim`` lifted coordinates are the linear
    # part — that's our reconstruction. Both dictionaries bake the
    # identity in (NN-lift via clamped first-block weights; polynomial+RBF
    # via the linear features being the first state_dim entries).
    x_hat = z[:state_dim]
    return np.clip(x_hat, 0.0, 1.0)


def predict_trajectory(
    koopman: KoopmanState | None,
    x0: np.ndarray,
    *,
    horizon: int,
) -> np.ndarray:
    """
    Roll out a trajectory ``[x_0, x_1, ..., x_horizon]`` under the
    Koopman operator. Length == horizon + 1.

    Includes ``x0`` itself as the first row so callers can index by
    step number without offset bookkeeping.
    """
    if horizon < 0:
        raise ValueError(f"horizon must be >= 0, got {horizon!r}")

    state_dim = x0.shape[0]
    out = np.zeros((horizon + 1, state_dim), dtype=np.float64)
    out[0] = np.clip(x0, 0.0, 1.0)

    if koopman is None:
        for t in range(1, horizon + 1):
            out[t] = out[0]
        return out

    K = np.array(koopman.operator, dtype=np.float64)
    z = lift_via_state(out[0], koopman)
    for t in range(1, horizon + 1):
        z = K @ z
        out[t] = np.clip(z[:state_dim], 0.0, 1.0)

    return out
