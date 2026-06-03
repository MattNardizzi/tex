"""
SCCAL — Semantic-Geometric Coupled-dynamics Cascading-risk AuditIng Layer.

Thread 9. Reference: arxiv 2603.13325 (Auditing Cascading Risks in
Multi-Agent Systems via Semantic-Geometric Co-evolution, ICLR 2026
Workshop on Principled Design for Trustworthy AI). Background:
arxiv 2605.11645 (GeomHerd, Ollivier-Ricci curvature on agent-action
graphs) for the geometric component.

What this module does
---------------------
Computes a forward-looking systemic-risk signal by tracking how the
*semantic flow* (what agents are saying/doing) and the *geometric
curvature* of the interaction graph co-evolve. Per the SCCAL paper:

    "Curvature anomalies systematically precede explicit semantic
     violations by several interaction turns, enabling proactive
     intervention. The local nature of Ricci curvature provides
     principled interpretability for root-cause attribution."

The signal is the *consistency violation* between two predictors:
  * ψ — Geometry-Aware Semantic Predictor: given current geometry,
    what semantic flow is expected?
  * ϕ — Semantic-Tension Geometric Predictor: given current semantic
    flow, what curvature pattern is expected?

When ψ and ϕ disagree with the actual measurements, the system is in
a structurally-tense regime: a cascade precursor. The deviation
magnitude is the SCCAL score in [0, 1].

Why this matters for Tex
------------------------
ProbGuard PCTL (Thread 7.1) computes retrospective probability — given
observed transitions so far, what's P[F^{<=k} unsafe]? Strong, but
backward-looking. SCCAL is forward-looking and fundamentally different
in kind: it sees the *structural tension* before the first PCTL
unsafe-state transition has happened.

We fuse both in ``risk_evaluator.score_fused()``: PCTL gives PAC
bounds on retrospective probability; SCCAL gives the "structural
weather forecast" that fires several turns ahead. The fusion is the
wedge — neither paper proposes the composition.

Pure NumPy, deterministic, no external deps.
"""

from __future__ import annotations

import math

import numpy as np
from pydantic import BaseModel, ConfigDict, Field


_MIN_GRAPH_NODES: int = 2
# Default OT-iteration cap for discrete Ollivier-Ricci. With a small
# Sinkhorn relaxation this converges in well under 50 iters on the
# governance-graph scale (< 200 nodes).
_OT_MAX_ITERS: int = 100
_OT_EPS: float = 5e-4
# Thread 9.1: switch to exact discrete-OT (network simplex) when the
# combined support size is small enough that the LP is cheap. For
# the governance-graph scale (< 200 nodes) this hits every typical
# edge. We use scipy.optimize.linprog (HIGHS backend) when available
# and fall back to log-domain Sinkhorn otherwise.
_EXACT_OT_MAX_SUPPORT: int = 64

try:  # pragma: no cover — optional dep
    from scipy.optimize import linprog as _scipy_linprog  # type: ignore
    _HAS_SCIPY = True
except Exception:  # pragma: no cover
    _scipy_linprog = None  # type: ignore
    _HAS_SCIPY = False


class SCCALSignal(BaseModel):
    """Frozen output of one SCCAL evaluation."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    score: float = Field(..., ge=0.0, le=1.0, description="SCCAL risk in [0, 1].")
    mean_curvature: float = Field(..., description="Mean ORC across edges.")
    curvature_variance: float = Field(..., ge=0.0)
    semantic_tension: float = Field(..., ge=0.0)
    coupled_violation: float = Field(..., ge=0.0)
    # Thread 9.1: curvature-gated attention recurrence divergence.
    # Zero when no semantic flow is provided (geometry-only mode).
    curvature_gated_divergence: float = Field(default=0.0, ge=0.0, le=1.0)
    n_nodes: int = Field(..., ge=0)
    n_edges: int = Field(..., ge=0)
    # Per-edge attribution: edges with the most negative curvature are
    # the most likely cascade bottlenecks (per Sia et al. 2019, also
    # cited by the SCCAL paper). We expose the top-K for root-cause.
    top_negative_curvature_edges: tuple[tuple[str, str, float], ...] = Field(
        default=(),
        description="(source, target, ORC) for the K most-negative edges.",
    )


def _wasserstein1_1d_via_sort(
    p_supp: np.ndarray, p_weights: np.ndarray,
    q_supp: np.ndarray, q_weights: np.ndarray,
) -> float:
    """
    Sort-based 1D Wasserstein-1 distance between two discrete
    distributions on the line. We project onto a 1D embedding for
    the cheap case (used as a sentinel + sanity check).
    """
    # Sort by support, then compute CDF L1.
    pi = np.argsort(p_supp)
    qi = np.argsort(q_supp)
    p_s = p_supp[pi]
    p_w = p_weights[pi]
    q_s = q_supp[qi]
    q_w = q_weights[qi]

    # Pool all support points, integrate |F_p - F_q| dx.
    supp = np.concatenate([p_s, q_s])
    supp = np.sort(np.unique(supp))
    if supp.size < 2:
        return 0.0

    def cdf(s_pts: np.ndarray, w: np.ndarray, grid: np.ndarray) -> np.ndarray:
        # Cumulative weight at each grid point.
        idx = np.searchsorted(s_pts, grid, side="right")
        csum = np.concatenate([[0.0], np.cumsum(w)])
        return csum[idx]

    Fp = cdf(p_s, p_w, supp)
    Fq = cdf(q_s, q_w, supp)
    widths = np.diff(supp)
    integrand = np.abs(Fp[:-1] - Fq[:-1])
    return float(np.sum(integrand * widths))


def _wasserstein1_exact_lp(
    p_idx: np.ndarray, p_w: np.ndarray,
    q_idx: np.ndarray, q_w: np.ndarray,
    cost: np.ndarray,
) -> float:
    """
    Exact Wasserstein-1 between two discrete distributions via LP.

    Thread 9.1: bleeding-edge ORC implementations (e.g. GraphRicciCurvature
    with the OTD backend) use exact network-simplex / LP for small
    supports, falling back to Sinkhorn for large ones. We follow the
    same pattern: scipy.optimize.linprog with HiGHS solves the
    Monge-Kantorovich LP in milliseconds for ≤ 64 supports.

    Formulation (standard discrete OT LP):
       min  sum_ij c_ij t_ij
       s.t. sum_j t_ij = a_i  ∀i
            sum_i t_ij = b_j  ∀j
            t_ij ≥ 0
    """
    if not _HAS_SCIPY:  # pragma: no cover — guard, callers check first
        return _wasserstein1_sinkhorn(p_idx, p_w, q_idx, q_w, cost)

    C = cost[np.ix_(p_idx, q_idx)]
    a = p_w.astype(np.float64)
    b = q_w.astype(np.float64)
    a_sum = a.sum()
    b_sum = b.sum()
    if a_sum <= 0 or b_sum <= 0:
        return 0.0
    a = a / a_sum
    b = b / b_sum

    n, m = C.shape
    c = C.flatten()

    # Equality constraints: row marginals (n) + col marginals (m).
    # Drop one row to avoid redundancy (sum a = sum b = 1 makes
    # n+m constraints rank n+m-1).
    A_eq_rows = []
    b_eq = []
    for i in range(n):
        row = np.zeros(n * m)
        row[i * m : (i + 1) * m] = 1.0
        A_eq_rows.append(row)
        b_eq.append(a[i])
    for j in range(m - 1):  # drop last col constraint
        col = np.zeros(n * m)
        col[j :: m] = 1.0
        A_eq_rows.append(col)
        b_eq.append(b[j])

    A_eq = np.array(A_eq_rows)
    res = _scipy_linprog(
        c=c, A_eq=A_eq, b_eq=np.array(b_eq),
        bounds=(0.0, None), method="highs",
    )
    if not res.success:  # pragma: no cover — LP infeasible (shouldn't happen)
        return _wasserstein1_sinkhorn(p_idx, p_w, q_idx, q_w, cost)
    return float(res.fun)


def _wasserstein1_sinkhorn(
    p_idx: np.ndarray, p_w: np.ndarray,
    q_idx: np.ndarray, q_w: np.ndarray,
    cost: np.ndarray,
) -> float:
    """Log-domain Sinkhorn — fallback for large supports."""
    C = cost[np.ix_(p_idx, q_idx)]
    a = p_w.astype(np.float64)
    b = q_w.astype(np.float64)

    a_sum = a.sum()
    b_sum = b.sum()
    if a_sum <= 0 or b_sum <= 0:
        return 0.0
    a = a / a_sum
    b = b / b_sum

    log_a = np.log(np.clip(a, 1e-300, None))
    log_b = np.log(np.clip(b, 1e-300, None))
    f = np.zeros_like(a)
    g = np.zeros_like(b)
    eps = _OT_EPS

    def _logsumexp(M: np.ndarray, axis: int) -> np.ndarray:
        m = M.max(axis=axis, keepdims=True)
        return (m.squeeze(axis) + np.log(np.sum(np.exp(M - m), axis=axis)))

    for _ in range(_OT_MAX_ITERS):
        M = (g[None, :] - C) / eps
        f_new = -eps * _logsumexp(M, axis=1) + eps * log_a
        M = (f_new[:, None] - C) / eps
        g_new = -eps * _logsumexp(M, axis=0) + eps * log_b
        if np.allclose(f, f_new, atol=1e-7) and np.allclose(g, g_new, atol=1e-7):
            f, g = f_new, g_new
            break
        f, g = f_new, g_new

    T = np.exp((f[:, None] + g[None, :] - C) / eps)
    return float(np.sum(T * C))


def _wasserstein1_general(
    p_idx: np.ndarray, p_w: np.ndarray,
    q_idx: np.ndarray, q_w: np.ndarray,
    cost: np.ndarray,
) -> float:
    """
    Wasserstein-1 dispatcher. Uses exact LP when support is small enough
    (and scipy is available), otherwise log-domain Sinkhorn.

    Per Thread 9.1: for governance-graph scale (< 64-node combined
    support), exact OT runs in milliseconds and preserves the discrete-
    Ricci curvature math without Sinkhorn's regularization bias.
    """
    combined_support = p_idx.size + q_idx.size
    if _HAS_SCIPY and combined_support <= _EXACT_OT_MAX_SUPPORT:
        return _wasserstein1_exact_lp(p_idx, p_w, q_idx, q_w, cost)
    return _wasserstein1_sinkhorn(p_idx, p_w, q_idx, q_w, cost)


def _shortest_paths(adj: np.ndarray) -> np.ndarray:
    """
    All-pairs shortest paths via Floyd-Warshall. Adjacency is a
    binary directed matrix; we treat it as undirected for ORC
    (the discrete-Ricci literature is undirected by default).
    """
    n = adj.shape[0]
    # Symmetrize.
    A = ((adj + adj.T) > 0).astype(np.float64)
    INF = 1e9
    D = np.where(A > 0, 1.0, INF)
    np.fill_diagonal(D, 0.0)
    for k in range(n):
        D = np.minimum(D, D[:, k : k + 1] + D[k : k + 1, :])
    return D


def _ollivier_ricci_for_edge(
    u: int, v: int,
    adj: np.ndarray, sp: np.ndarray,
    alpha: float = 0.5,
) -> float:
    """
    Ollivier-Ricci curvature for edge (u, v).

    Mass distribution mu_u(w) = alpha if w == u, (1 - alpha) / deg(u) if
    w is a neighbor of u, 0 else. Standard discrete-Ricci definition
    (Ollivier 2007, Sia 2019).

    Curvature kappa(u, v) = 1 - W_1(mu_u, mu_v) / d(u, v).

    Positive curvature → edge is in a "convex" / clique-like region
    (information aggregates; potential herding).
    Negative curvature → edge is a bridge between communities
    (information spreads; potential contagion).
    """
    n = adj.shape[0]
    deg_u = float(np.sum(adj[u] + adj[:, u] > 0))
    deg_v = float(np.sum(adj[v] + adj[:, v] > 0))
    if deg_u == 0 or deg_v == 0:
        return 0.0

    nbrs_u = np.where((adj[u] + adj[:, u]) > 0)[0]
    nbrs_v = np.where((adj[v] + adj[:, v]) > 0)[0]

    if nbrs_u.size == 0 or nbrs_v.size == 0:
        return 0.0

    p_idx = np.concatenate([[u], nbrs_u])
    p_w = np.concatenate([[alpha], np.full(nbrs_u.size, (1 - alpha) / deg_u)])
    q_idx = np.concatenate([[v], nbrs_v])
    q_w = np.concatenate([[alpha], np.full(nbrs_v.size, (1 - alpha) / deg_v)])

    edge_dist = float(sp[u, v])
    if edge_dist <= 0:
        return 0.0

    W1 = _wasserstein1_general(p_idx, p_w, q_idx, q_w, sp)
    return float(1.0 - W1 / edge_dist)


def compute_curvature(adj: np.ndarray) -> tuple[np.ndarray, float, float]:
    """
    Compute Ollivier-Ricci curvature for every edge in the graph.

    Returns:
      kappa: dense (n, n) curvature matrix (0 where no edge).
      mean_kappa: scalar.
      var_kappa: scalar variance across edges.
    """
    n = adj.shape[0]
    if n < _MIN_GRAPH_NODES:
        return np.zeros((max(n, 1), max(n, 1))), 0.0, 0.0

    sp = _shortest_paths(adj)
    edges = np.argwhere(adj > 0)
    kappa = np.zeros_like(adj, dtype=np.float64)
    vals: list[float] = []
    for u, v in edges:
        k = _ollivier_ricci_for_edge(int(u), int(v), adj, sp)
        kappa[u, v] = k
        vals.append(k)
    if not vals:
        return kappa, 0.0, 0.0
    arr = np.array(vals, dtype=np.float64)
    return kappa, float(arr.mean()), float(arr.var())


def _semantic_tension(semantic_flow: np.ndarray) -> float:
    """
    Semantic tension: a scalar measure of how 'stretched' the semantic
    flow vectors are across the graph. We use the average L2 norm of
    flow vectors, normalized to [0, 1] via a soft cap at norm=1.

    Higher tension → agents are pushing strongly in directions; in
    combination with low curvature (bridges) this is the SCCAL
    contagion regime.

    semantic_flow: shape (n_edges, d_embed) — directed flow vector per
    edge. We treat zero-norm rows as silent.
    """
    if semantic_flow.size == 0:
        return 0.0
    norms = np.linalg.norm(semantic_flow, axis=1)
    # Use mean of soft-capped tanh — bounded in [0, 1).
    return float(np.tanh(norms.mean()))


def _coupled_violation(
    kappa_vals: np.ndarray,
    semantic_norms: np.ndarray,
) -> float:
    """
    Coupled-dynamics consistency violation.

    SCCAL paper §3.4: ψ predicts semantic flow from geometry,
    ϕ predicts geometry from semantic flow; their consistency is the
    co-evolutionary signal. In stable collaboration, low geometric
    tension (curvature near zero) should match low semantic tension
    (small flow norms), and vice versa.

    Practical proxy: rank-correlation deviation. If the ranking of
    edges by semantic norm doesn't match the ranking by |curvature|,
    the system is desynchronized — which is what SCCAL flags.

    Returns a value in [0, 1] where 0 = perfectly co-evolving and 1 =
    maximally violated.
    """
    if kappa_vals.size != semantic_norms.size or kappa_vals.size < 2:
        return 0.0
    # Spearman-like deviation: 1 - |rank_correlation|.
    def _rank(x: np.ndarray) -> np.ndarray:
        order = np.argsort(x)
        ranks = np.empty_like(order, dtype=np.float64)
        ranks[order] = np.arange(x.size)
        return ranks

    r_k = _rank(np.abs(kappa_vals))
    r_s = _rank(semantic_norms)
    # Pearson on ranks = Spearman.
    r_k_c = r_k - r_k.mean()
    r_s_c = r_s - r_s.mean()
    denom = math.sqrt((r_k_c ** 2).sum() * (r_s_c ** 2).sum())
    if denom <= 0:
        return 0.0
    rho = float((r_k_c * r_s_c).sum() / denom)
    return float(np.clip(1.0 - abs(rho), 0.0, 1.0))


# =============================================================================
# Thread 9.1: Curvature-gated attention recurrence
# =============================================================================
# The SCCAL paper specifies a curvature-gated recurrent architecture where
# attention weights between agents are *multiplicatively modulated* by edge
# curvature (structural stability). Connects to "Gating Enables Curvature"
# (arxiv 2604.14702, Apr 2026): multiplicative gating is what enables
# non-flat representational geometry. We implement the recurrence with
# Glorot-init gates trained nowhere — we use the gating *mechanism* (not
# a learned parameter set) since the paper's contribution is the math, not
# specific weight values.
#
# Mechanism (paper §3.3):
#   Let g_ij(t) = sigmoid(c_ij) be the curvature gate for edge (i, j)
#   at time t.  Standard softmax attention assigns weight α_ij to neighbor
#   j of i. The curvature-gated update is:
#       α_ij_gated = α_ij ⊙ g_ij    (then re-normalize)
#       h_i(t+1)   = sum_j α_ij_gated · h_j(t)
#
# The bidirectional version (ψ and ϕ predictors) is:
#       h_sem(t+1) = sum_j α_ij_gated * h_sem_j(t)   # geometry-aware semantic
#       h_geo(t+1) = sum_j β_ij_sem    * h_geo_j(t)  # semantic-aware geometry
# where β_ij_sem is the semantic-tension-modulated attention. The
# co-evolutionary violation is the divergence between these two updates.
# =============================================================================


def _sigmoid(x: np.ndarray) -> np.ndarray:
    return 1.0 / (1.0 + np.exp(-x))


def _softmax_rows(M: np.ndarray) -> np.ndarray:
    """Row-wise softmax with numerical stability."""
    M_shift = M - M.max(axis=1, keepdims=True)
    e = np.exp(M_shift)
    s = e.sum(axis=1, keepdims=True)
    s = np.where(s > 0, s, 1.0)
    return e / s


def curvature_gated_attention_step(
    *,
    kappa: np.ndarray,
    adj: np.ndarray,
    h_sem: np.ndarray,
    h_geo: np.ndarray,
    semantic_flow_per_node: np.ndarray | None = None,
) -> tuple[np.ndarray, np.ndarray, float]:
    """
    One step of bidirectional curvature-gated attention recurrence.

    Implements the SCCAL paper's coupled-dynamics mechanism: the
    geometry-aware semantic predictor (ψ) and the semantic-aware
    geometry predictor (ϕ) each propagate node states via attention
    that is multiplicatively gated by curvature (for ψ) or semantic
    flow norm (for ϕ).

    Parameters
    ----------
    kappa : (n, n) ndarray
        Per-edge Ollivier-Ricci curvature. Zero where no edge.
    adj : (n, n) ndarray
        Binary adjacency mask. Non-edges get α = 0.
    h_sem : (n, d_sem) ndarray
        Current per-node semantic state.
    h_geo : (n, d_geo) ndarray
        Current per-node geometric state.
    semantic_flow_per_node : (n, d_sem) ndarray, optional
        Per-node semantic flow magnitude. If None, derived from h_sem.

    Returns
    -------
    h_sem_next : (n, d_sem)
        Geometry-aware semantic update (ψ predictor output).
    h_geo_next : (n, d_geo)
        Semantic-aware geometric update (ϕ predictor output).
    coupled_divergence : float
        Scalar measure of disagreement between the two predictors,
        in [0, 1]. This is the SCCAL forward-looking signal.
    """
    n = adj.shape[0]
    if n < 2:
        return h_sem.copy(), h_geo.copy(), 0.0

    # Mask non-edges to -inf before softmax (so α = 0 there).
    mask = (adj > 0).astype(np.float64)
    raw_attention = mask * 1.0  # uniform pre-gate raw scores on edges
    raw_attention = np.where(mask > 0, raw_attention, -1e9)

    # ψ predictor: curvature-gated attention for semantic flow.
    # Edges with positive curvature (herding) get MORE weight to dampen
    # tension; edges with negative curvature (bridges) get LESS weight,
    # which is paradoxical in the paper's sign convention. Re-reading
    # §3.3: gate = sigmoid(kappa), so positive kappa → high gate weight
    # (information flows freely in stable regions), negative kappa →
    # low gate weight (bridges throttle).
    gate_sem = _sigmoid(2.0 * kappa) * mask
    alpha_sem = _softmax_rows(raw_attention) * gate_sem
    # Re-normalize per row after gating.
    row_sums = alpha_sem.sum(axis=1, keepdims=True)
    row_sums = np.where(row_sums > 1e-12, row_sums, 1.0)
    alpha_sem = alpha_sem / row_sums
    h_sem_next = alpha_sem @ h_sem

    # ϕ predictor: semantic-tension-gated attention for geometric state.
    if semantic_flow_per_node is None:
        # Derive flow magnitude from semantic state norms.
        node_sem_norms = np.linalg.norm(h_sem, axis=1)
    else:
        node_sem_norms = np.linalg.norm(semantic_flow_per_node, axis=1)
    # Edge-level tension: average of endpoint norms.
    tension_edge = 0.5 * (node_sem_norms[:, None] + node_sem_norms[None, :])
    # High tension → low gate (semantic pressure breaks geometric stability).
    gate_geo = _sigmoid(-2.0 * tension_edge) * mask
    alpha_geo = _softmax_rows(raw_attention) * gate_geo
    row_sums = alpha_geo.sum(axis=1, keepdims=True)
    row_sums = np.where(row_sums > 1e-12, row_sums, 1.0)
    alpha_geo = alpha_geo / row_sums
    h_geo_next = alpha_geo @ h_geo

    # Co-evolutionary divergence: KL-ish between the two attention
    # distributions, averaged over rows. Bounded to [0, 1] via sigmoid.
    # When ψ and ϕ agree, the gated attention matrices are similar; when
    # they disagree (semantic and geometric flows fight each other), the
    # KL grows — and the system is in the SCCAL contagion regime.
    eps = 1e-12
    p = alpha_sem + eps
    q = alpha_geo + eps
    p = p / p.sum(axis=1, keepdims=True)
    q = q / q.sum(axis=1, keepdims=True)
    kl_rows = np.sum(p * np.log(p / q), axis=1)
    mean_kl = float(np.clip(np.mean(kl_rows), 0.0, np.inf))
    divergence = float(np.clip(1.0 - np.exp(-mean_kl), 0.0, 1.0))

    return h_sem_next, h_geo_next, divergence


def curvature_gated_recurrence(
    *,
    kappa: np.ndarray,
    adj: np.ndarray,
    semantic_flow_per_node: np.ndarray,
    steps: int = 4,
) -> tuple[float, np.ndarray]:
    """
    Run T steps of the curvature-gated bidirectional attention recurrence
    and return (mean_divergence_over_horizon, final_semantic_state).

    SCCAL paper §3.5 reports that the divergence accumulated over a
    short horizon is the forward-looking signal that fires several turns
    before explicit semantic violation. We compute the *mean* (not max)
    over the horizon because a single spike can be a healthy
    disagreement that resolves; sustained divergence is the bad signal.
    """
    if steps < 1:
        return 0.0, semantic_flow_per_node.copy()

    n, d = semantic_flow_per_node.shape
    h_sem = semantic_flow_per_node.copy()
    h_geo = kappa.copy()[:, :d] if kappa.shape[1] >= d else np.zeros((n, d))
    # Geometric state init: project curvature row-sums into d-dim space.
    deg = (adj > 0).sum(axis=1).astype(np.float64)
    row_sum_kappa = kappa.sum(axis=1)
    geo_scalar = np.where(deg > 0, row_sum_kappa / np.maximum(deg, 1.0), 0.0)
    h_geo = np.tile(geo_scalar[:, None], (1, d))

    divergences: list[float] = []
    for _ in range(steps):
        h_sem, h_geo, div = curvature_gated_attention_step(
            kappa=kappa, adj=adj, h_sem=h_sem, h_geo=h_geo,
            semantic_flow_per_node=semantic_flow_per_node,
        )
        divergences.append(div)

    return float(np.mean(divergences)), h_sem


def compute_sccal(
    *,
    adj: np.ndarray,
    semantic_flow: np.ndarray,
    edge_labels: tuple[tuple[str, str], ...] = (),
    top_k_attribution: int = 5,
    enable_curvature_gated_recurrence: bool = True,
    recurrence_steps: int = 4,
) -> SCCALSignal:
    """
    Compute the SCCAL signal for the current interaction graph.

    Thread 9.1: when ``enable_curvature_gated_recurrence=True`` and a
    real ``semantic_flow`` is provided, the SCCAL paper's full bidirectional
    curvature-gated attention recurrence (§3.3) is run for
    ``recurrence_steps`` steps. The mean divergence between the ψ (geometry-
    aware semantic) and ϕ (semantic-aware geometric) predictors is added
    to the composite score as the forward-looking forecast term.

    Parameters
    ----------
    adj : (n, n) ndarray
        Binary directed adjacency. ``adj[u, v] = 1`` ⇒ agent u currently
        communicating with / acting on v.
    semantic_flow : (n_edges, d) ndarray
        Per-edge semantic flow vector. Row order MUST match
        ``np.argwhere(adj > 0)`` traversal order. Pass empty (0, 0) to
        skip semantic coupling (geometry-only mode).
    edge_labels : tuple of (source_name, target_name)
        Human-readable edge labels for root-cause attribution output.
    top_k_attribution : int
        Number of most-negative-curvature edges to surface.
    enable_curvature_gated_recurrence : bool
        Run the full bidirectional curvature-gated attention recurrence.
        Default True; set False for the pure-static-signal fallback.
    recurrence_steps : int
        Horizon for the recurrence; SCCAL paper uses 4-8.

    Returns
    -------
    SCCALSignal with score in [0, 1].
    """
    if adj.ndim != 2 or adj.shape[0] != adj.shape[1]:
        raise ValueError(f"adj must be square 2-D, got {adj.shape!r}")

    n = adj.shape[0]
    if n < _MIN_GRAPH_NODES:
        return SCCALSignal(
            score=0.0,
            mean_curvature=0.0,
            curvature_variance=0.0,
            semantic_tension=0.0,
            coupled_violation=0.0,
            curvature_gated_divergence=0.0,
            n_nodes=int(n),
            n_edges=0,
            top_negative_curvature_edges=(),
        )

    kappa, mean_k, var_k = compute_curvature(adj)
    edges_idx = np.argwhere(adj > 0)
    n_edges = int(edges_idx.shape[0])
    if n_edges == 0:
        return SCCALSignal(
            score=0.0,
            mean_curvature=0.0,
            curvature_variance=0.0,
            semantic_tension=0.0,
            coupled_violation=0.0,
            curvature_gated_divergence=0.0,
            n_nodes=int(n),
            n_edges=0,
            top_negative_curvature_edges=(),
        )

    kappa_vals = np.array([kappa[u, v] for u, v in edges_idx])

    coupled = 0.0
    tension = 0.0
    cg_divergence = 0.0

    if semantic_flow.size > 0 and semantic_flow.shape[0] == n_edges:
        sem_norms = np.linalg.norm(semantic_flow, axis=1)
        tension = _semantic_tension(semantic_flow)
        coupled = _coupled_violation(kappa_vals, sem_norms)

        # Curvature-gated attention recurrence (Thread 9.1 — the SCCAL
        # paper's actual mechanism). Aggregate edge-level semantic flow
        # to per-node by sum over outgoing edges.
        if enable_curvature_gated_recurrence:
            d_sem = semantic_flow.shape[1]
            sem_per_node = np.zeros((n, d_sem))
            for ei, (u, v) in enumerate(edges_idx):
                sem_per_node[int(u)] += semantic_flow[ei]
            cg_divergence, _ = curvature_gated_recurrence(
                kappa=kappa,
                adj=adj,
                semantic_flow_per_node=sem_per_node,
                steps=recurrence_steps,
            )
    else:
        # Geometry-only mode: |curvature| spread itself as tension proxy.
        tension = float(np.clip(math.sqrt(var_k) * 2.0, 0.0, 1.0))
        coupled = float(np.clip(math.sqrt(var_k), 0.0, 1.0))
        cg_divergence = 0.0

    # Negative-curvature concentration → contagion risk. Sigmoid-cap.
    neg_mass = float(np.clip(-mean_k, 0.0, 1.0))

    # Composite SCCAL score: weighted of the four signals.
    # Thread 9.1: when the curvature-gated recurrence fires, it gets
    # 0.40 weight (paper's headline mechanism), coupled-rank-violation
    # drops to 0.25, neg_mass 0.20, tension 0.15.
    # When recurrence is off (geometry-only), revert to the Thread 9
    # weights: 0.55 coupled, 0.25 neg, 0.20 tension.
    if cg_divergence > 0:
        score = float(
            np.clip(
                0.40 * cg_divergence
                + 0.25 * coupled
                + 0.20 * neg_mass
                + 0.15 * tension,
                0.0, 1.0,
            )
        )
    else:
        score = float(
            np.clip(
                0.55 * coupled + 0.25 * neg_mass + 0.20 * tension,
                0.0, 1.0,
            )
        )

    # Top-K most-negative-curvature edges for root-cause attribution.
    order = np.argsort(kappa_vals)  # ascending: most negative first
    top_k = order[: min(top_k_attribution, kappa_vals.size)]
    attribution: list[tuple[str, str, float]] = []
    for rank_idx in top_k:
        u, v = edges_idx[rank_idx]
        src = edge_labels[rank_idx][0] if rank_idx < len(edge_labels) else f"node_{u}"
        tgt = edge_labels[rank_idx][1] if rank_idx < len(edge_labels) else f"node_{v}"
        attribution.append((src, tgt, float(kappa_vals[rank_idx])))

    return SCCALSignal(
        score=score,
        mean_curvature=float(mean_k),
        curvature_variance=float(var_k),
        semantic_tension=float(tension),
        coupled_violation=float(coupled),
        curvature_gated_divergence=float(cg_divergence),
        n_nodes=int(n),
        n_edges=n_edges,
        top_negative_curvature_edges=tuple(attribution),
    )
