"""
P1–P4 — the NETWORK-EGRESS plane (``PlaneId.NETWORK_EGRESS``).

The highest-leverage UNIVERSAL net (RESEARCH_LOG.md §1 P1–P4). A directory
sees agents that authenticate through it; a cloud-audit log sees agents on that
cloud. Neither sees the CLI script on a laptop, the cron job on a forgotten VM,
or the server-side daemon holding a personal API key. The ONE thing every agent
must do is talk to a model/tool/MCP endpoint over the network — that egress is
the signal, and it is observed at a chokepoint the workload cannot bypass while
still reaching a model. Metadata only; never payload (the privacy line the gate
holds, this plane holds too).

Four fused passive facets (ARCHITECTURE.md §8, RESEARCH_LOG.md P1–P4):

- **P1 JA4 client-hello** — hashes the TLS ClientHello: the *client stack*
  (httpx/OpenAI-SDK, Go net/http, aiohttp, curl, Playwright) has a stable
  fingerprint even as IPs and certs rotate. An anonymity SET, **not** an
  identity — demoted to a weak BRIDGING edge (a JA4 shared by millions carries
  ≈0 evidence after the N5 ``1/anon_set_size`` discount).
- **P2 JA4S / cert-SPKI** — the server-hello + cert SPKI: destination-attribution
  even under ECH, where the inner SNI is encrypted. The ECH-blinded fallback.
- **P3 HTTP/2 framing** — the h2 SETTINGS/WINDOW_UPDATE/pseudo-header-order
  hash: an INDEPENDENT client-stack signature used as a coherence oracle vs JA4
  (JA4=Chrome but h2=Go ⇒ forgery alarm — the N4 incoherence detector input).
- **P4 token waveform** — the streamed TLS record-size + inter-arrival series:
  THAT a flow is an LLM agent loop, and the packetization MODE (1:1 vs bundled).

The BEHAVIORAL layer the old stub lacked (the load-bearing addition):

- ``token_waveform_sig`` — a quantized signature of the streamed token
  packetization. ``1:1`` per-token framing is a human-driving-a-chatbot-UI tell;
  ``bundled`` multi-token records is an API/agent tell. So an AGENT is
  distinguishable from a HUMAN behind one egress (ARCHITECTURE.md §3B).
- ``cadence_sig`` — a quantized signature of the inter-arrival/burst entropy of
  a flow's request series. Two agents behind ONE egress IP/credential differ in
  their request cadence (a tight low-entropy cron loop vs a bursty interactive
  loop), so the split-axis can separate them (ARCHITECTURE.md §3A / §1.2).

These two behavioral signatures are what let the resolver SPLIT two agents
collapsed behind one egress and distinguish an agent from a human — the old
mock could only group by ``(workload, ja4, sni)`` and had no behavioral axis.

Footprint emitted (the fields fuse.py / disambiguate.py key on)::

    keys:  {ja4, ja4s, sni, asn, egress_ip, h2_settings_hash,
            token_waveform_sig, cadence_sig}      (all BRIDGING-grade — §fuse)
    attrs: {model_provider, source_workload, connection_count,
            packetization_mode, alpn, byte_total, flow_count, ...}

Every key is BRIDGING-grade by SCHEMA (``fuse._BRIDGING_KEYS``): a shared TLS/
HTTP/behavioral fingerprint LINKS two flows but never MERGES two distinct agents
alone — a popular value is shared by millions, so the N5 ``1/anon_set_size``
discount drives its evidence to ≈0. The plane is a universal NET, not an
identity claim; identity comes from fusing it with a stronger plane.

Source + shim (the HARD RULE for collectors that cannot run on macOS):

- The real source is a list/iterator of TLS/HTTP2 flow records (an OCSF/Zeek/
  Suricata/forward-proxy/VPC-flow feed joined to a JA4 store). Real passive
  packet capture cannot run portably on a dev mac, so the sensor consumes an
  already-extracted flow-record stream (the shape a Zeek/Security-Lake export
  emits) rather than sniffing packets itself. ``parse_ocsf_flow_records`` is the
  real parser over that JSON shape.
- ``LocalFlowFixtureSource`` is a CLEARLY-LABELED local shim that reads a fixture
  file of the SAME flow-record shape (it is NOT a fake passive sensor — it reads
  the identical event schema a real Zeek export would, off disk). It exists so
  the plane is testable on macOS without a kernel tap.

Degrade-to-empty: no flow source / unreadable fixture / no model-endpoint egress
⇒ zero incidences. The sensor NEVER raises and NEVER fabricates a flow.

Catchability here is an ASSERTED plane constant (a slice/breadth constant, NOT a
measured recall; measurement is a Phase-5 signed-cohort target). The count-based
estimator carries-but-does-not-consume it.
"""

from __future__ import annotations

import json
import math
from collections import defaultdict
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Callable, Iterable, Iterator, Mapping, Sequence

from tex.discovery.engine.models import (
    Admissibility,
    FootprintField,
    FootprintVector,
    Incidence,
    PlaneId,
)
from tex.discovery.engine.sensors.base import SenseContext

# ---------------------------------------------------------------------------
# Plane constants
# ---------------------------------------------------------------------------

#: ASSERTED recall of the network-egress plane (a constant, NOT measured;
#: measurement deferred to Phase 5 signed-cohort calibration). The plane is a
#: universal passive net but a fully-emulated stack (utls/curl-impersonate) is a
#: NAMED blind spot, not folded into this recall. The count-based slice estimator
#: carries-but-does-not-consume this value.
NETWORK_EGRESS_CATCHABILITY: float = 1.0

#: This plane is passive-network OBSERVED: an out-of-process chokepoint sighting
#: the workload cannot suppress. Not PROVEN (no eBPF PID binding), not merely
#: CLAIMED (the agent did not declare it).
NETWORK_EGRESS_ADMISSIBILITY: Admissibility = Admissibility.OBSERVED

#: The activation env flag (ARCHITECTURE.md §8 — P1 JA4 is the roster anchor for
#: the whole network-egress plane). The sensor is built ONLY when this is truthy.
NETWORK_EGRESS_FLAG: str = "TEX_SIEVE_P1_JA4"

#: Env var naming the local fixture file the shim reads (the labeled local shim
#: path). Absent ⇒ the factory builds an inert sensor (degrade to empty).
NETWORK_EGRESS_FIXTURE_ENV: str = "TEX_SIEVE_P1_FLOW_FIXTURE"


# Known LLM / agent / MCP egress destinations (SNI / cert-name → provider).
# Matched as a suffix so regional subdomains resolve
# (bedrock-runtime.us-east-1.amazonaws.com → aws_bedrock). Conservative + a
# generic ``*.mcp.`` / ``*.modelcontext*`` catch so a custom MCP endpoint is
# still recognized as agent egress.
_MODEL_ENDPOINTS: dict[str, str] = {
    "api.openai.com": "openai",
    "api.anthropic.com": "anthropic",
    "generativelanguage.googleapis.com": "google",
    "aiplatform.googleapis.com": "google_vertex",
    "bedrock-runtime.amazonaws.com": "aws_bedrock",
    "bedrock-agentcore.amazonaws.com": "aws_bedrock_agentcore",
    "api.cohere.ai": "cohere",
    "api.cohere.com": "cohere",
    "api.mistral.ai": "mistral",
    "api.groq.com": "groq",
    "openai.azure.com": "azure_openai",
    "api.deepseek.com": "deepseek",
    "api.perplexity.ai": "perplexity",
    "api.x.ai": "xai",
}

#: Substrings that mark a generic MCP / agent endpoint when no exact provider
#: matches (so a self-hosted MCP server still reads as agent egress).
_MODEL_HOST_HINTS: tuple[str, ...] = (".mcp.", "modelcontext", "inference", "llm")


def provider_for_host(host: str) -> str | None:
    """Resolve a destination host (SNI / cert CN) to a model-endpoint provider.

    Returns the provider tag for a known model/agent/MCP endpoint, or ``None``
    for any non-model host (egress to a non-model host is NOT agent evidence).
    """
    if not host:
        return None
    low = host.casefold().strip().rstrip(".")
    for suffix, provider in _MODEL_ENDPOINTS.items():
        if low == suffix or low.endswith("." + suffix) or suffix in low:
            return provider
        # Regional/infix match: a provider whose service label leads the host but
        # whose apex is split by a region, e.g. ``bedrock-runtime.us-east-1.
        # amazonaws.com`` → ``bedrock-runtime.amazonaws.com``. Match when the
        # host's leading label AND the suffix's trailing apex both appear.
        head, _, apex = suffix.partition(".")
        if head and apex and low.startswith(head + ".") and low.endswith("." + apex):
            return provider
    for hint in _MODEL_HOST_HINTS:
        if hint in low:
            return "generic_model_endpoint"
    return None


# ---------------------------------------------------------------------------
# Flow-record source contract (real feed OR labeled local shim)
# ---------------------------------------------------------------------------

#: A flow source is any callable returning an iterable of raw flow-record dicts
#: (the shape a Zeek / Security-Lake OCSF / forward-proxy export emits). The
#: sensor extracts behavioral features from them — it never sniffs packets
#: itself (that cannot run portably on a dev mac; see module docstring).
FlowSource = Callable[[SenseContext], Iterable[Mapping[str, Any]]]


@dataclass(frozen=True)
class StaticFlowSource:
    """An in-memory flow source — the injected-list path (tests / a live feed).

    Mirrors the ``events=``/``flows=`` injection the existing connectors use:
    a deployment wraps its real Zeek/OCSF reader in this callable shape, and a
    test injects a fixture list. Degrades to empty on a ``None`` list.
    """

    flows: tuple[Mapping[str, Any], ...] = ()

    def __call__(self, context: SenseContext) -> Iterable[Mapping[str, Any]]:  # noqa: ARG002
        return self.flows


@dataclass(frozen=True)
class LocalFlowFixtureSource:
    """LABELED LOCAL SHIM — reads a fixture of the real flow-record shape.

    This is NOT a fake passive sensor and does not pretend to be one. Real
    passive TLS/HTTP2 capture (eBPF/packet capture) cannot run portably on a dev
    mac, so this shim reads a JSON/JSONL fixture off disk whose every record has
    the IDENTICAL schema a real Zeek/Security-Lake OCSF flow export emits, then
    hands it to the SAME ``parse_ocsf_flow_records`` parser the real feed uses.
    The feature-extraction path is byte-for-byte the production path; only the
    bytes' origin (a fixture file vs a live tap) differs, and that origin is
    named here so no caller can mistake it for live capture.

    Accepts either a JSON array of records or JSONL (one record per line).
    Degrades to empty on a missing/unreadable/malformed fixture; never raises.
    """

    fixture_path: Path

    def __call__(self, context: SenseContext) -> Iterable[Mapping[str, Any]]:  # noqa: ARG002
        try:
            path = Path(self.fixture_path)
            if not path.is_file():
                return ()
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return ()
        return _load_flow_text(text)


def _load_flow_text(text: str) -> tuple[Mapping[str, Any], ...]:
    """Parse a flow fixture body: a JSON array OR JSONL. Never raises."""
    text = text.strip()
    if not text:
        return ()
    # Try a single JSON document (array or {"flows": [...]}) first.
    try:
        doc = json.loads(text)
    except (ValueError, TypeError):
        doc = None
    if isinstance(doc, list):
        return tuple(r for r in doc if isinstance(r, dict))
    if isinstance(doc, dict) and isinstance(doc.get("flows"), list):
        return tuple(r for r in doc["flows"] if isinstance(r, dict))
    # Fall back to JSONL.
    records: list[Mapping[str, Any]] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            row = json.loads(line)
        except (ValueError, TypeError):
            continue
        if isinstance(row, dict):
            records.append(row)
    return tuple(records)


# ---------------------------------------------------------------------------
# OCSF/Zeek-style flow-record parser → a normalized flow feature view
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class FlowFeatures:
    """The normalized passive-egress feature view of ONE flow record.

    Extracted from a raw OCSF/Zeek-style flow-record dict by
    ``parse_ocsf_flow_records``. All fields are best-effort: a record missing a
    facet simply omits that key downstream (missing field = weight 0 in fuse,
    never a penalty). ``provider`` is ``None`` for a non-model destination, which
    the caller uses to drop the flow (non-model egress is not agent evidence).
    """

    source_workload: str | None
    ja4: str | None
    ja4s: str | None
    sni: str | None
    asn: str | None
    egress_ip: str | None
    h2_settings_hash: str | None
    alpn: str | None
    provider: str | None
    token_waveform_sig: str | None
    cadence_sig: str | None
    packetization_mode: str | None
    connection_count: int
    byte_total: int
    first_seen: datetime | None
    last_seen: datetime | None
    evidence_ref: str


def _coerce_str(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, str):
        s = value.strip()
        return s or None
    return str(value)


def _coerce_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _coerce_float_list(value: Any) -> list[float]:
    """Coerce a series field into a list of floats; non-numeric entries dropped."""
    if not isinstance(value, (list, tuple)):
        return []
    out: list[float] = []
    for v in value:
        try:
            out.append(float(v))
        except (TypeError, ValueError):
            continue
    return out


def _parse_iso(value: Any) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value.astimezone(UTC) if value.tzinfo else value.replace(tzinfo=UTC)
    if isinstance(value, (int, float)):
        try:
            return datetime.fromtimestamp(float(value), tz=UTC)
        except (OverflowError, OSError, ValueError):
            return None
    if not isinstance(value, str):
        return None
    s = value.strip()
    if not s:
        return None
    try:
        if s.endswith("Z"):
            s = s[:-1] + "+00:00"
        return datetime.fromisoformat(s).astimezone(UTC)
    except ValueError:
        return None


# --- OCSF/Zeek field aliasing -------------------------------------------------
# OCSF Network Activity (class 4001) nests TLS under ``tls`` and endpoints under
# ``src_endpoint``/``dst_endpoint``; Zeek ssl.log uses flat ``ja4``/``server_name``;
# a forward proxy uses ``sni``/``host``. We read all three shapes off one record.


def _dig(record: Mapping[str, Any], *paths: Sequence[str]) -> Any:
    """Return the first present value among several dotted key paths."""
    for path in paths:
        cur: Any = record
        ok = True
        for part in path:
            if isinstance(cur, Mapping) and part in cur:
                cur = cur[part]
            else:
                ok = False
                break
        if ok and cur not in (None, ""):
            return cur
    return None


def _extract_sni(record: Mapping[str, Any]) -> str | None:
    return _coerce_str(
        _dig(
            record,
            ("sni",),
            ("server_name",),
            ("tls", "sni"),
            ("tls", "server_name"),
            ("host",),
            ("dst_endpoint", "domain"),
        )
    )


def _extract_dst_name(record: Mapping[str, Any]) -> str | None:
    """The destination identity for provider resolution: SNI, else cert CN."""
    sni = _extract_sni(record)
    if sni:
        return sni
    # ECH-blinded fallback: the leaf cert subject CN names the destination.
    return _coerce_str(
        _dig(
            record,
            ("cert_cn",),
            ("tls", "certificate", "subject"),
            ("tls", "cert", "subject_cn"),
        )
    )


def _quantize_waveform(record: Mapping[str, Any]) -> tuple[str | None, str | None]:
    """Derive ``(token_waveform_sig, packetization_mode)`` from the record.

    P4: the streamed TLS record-size series leaks the packetization mode. We
    accept either an explicit ``packetization`` / ``packetization_mode`` field
    OR a ``record_sizes`` series we classify ourselves:

    - mean record size below ~24 bytes ⇒ ``1:1`` per-token framing (a human
      driving a chatbot UI / SSE-per-token);
    - larger / multi-token records ⇒ ``bundled`` (an API/agent call).

    The waveform signature is a coarse, quantized bucket of (mode, mean-size
    band) so two flows of the same SDK/provider share a signature while a
    different streaming shape differs. Quantized (not raw) so it generalizes
    across flows of one agent and stays a BRIDGING (anonymity-set) signal.
    """
    explicit = _coerce_str(
        _dig(record, ("packetization",), ("packetization_mode",), ("tls", "packetization"))
    )
    sizes = _coerce_float_list(
        _dig(record, ("record_sizes",), ("tls", "record_sizes"), ("token_sizes",))
    )
    mode: str | None = None
    if explicit:
        mode = explicit.casefold()
        if mode in ("1:1", "one_to_one", "per_token", "single"):
            mode = "1:1"
        elif mode in ("bundled", "batched", "multi", "api"):
            mode = "bundled"
    if mode is None and sizes:
        mean = sum(sizes) / len(sizes)
        mode = "1:1" if mean <= 24.0 else "bundled"

    if mode is None and not sizes:
        return (None, None)

    # Quantize the mean record size into a coarse band so the signature is
    # stable across an agent's flows but separates distinct streaming shapes.
    band = "na"
    if sizes:
        mean = sum(sizes) / len(sizes)
        if mean <= 24.0:
            band = "lo"
        elif mean <= 128.0:
            band = "mid"
        elif mean <= 1024.0:
            band = "hi"
        else:
            band = "xl"
    sig = f"wf:{mode or 'unknown'}:{band}"
    return (sig, mode)


def _quantize_cadence(record: Mapping[str, Any]) -> str | None:
    """Derive ``cadence_sig`` from the flow's inter-arrival / burst series (P4).

    Accepts either an explicit ``cadence_sig`` OR an ``inter_arrival_ms`` series
    we summarize ourselves. The signature is a coarse bucket of (rate band,
    burstiness band) computed from the inter-arrival mean and its normalized
    entropy:

    - a TIGHT, low-entropy series (a cron/poll loop firing on a fixed period) →
      ``cad:fast:periodic`` / ``cad:slow:periodic``;
    - a BURSTY, high-entropy series (an interactive agent loop / human-paced) →
      ``cad:*:bursty``.

    Two agents behind ONE egress IP/credential differ here (a tight loop vs a
    bursty one), so this is the split-axis that separates them
    (ARCHITECTURE.md §3A). Quantized so it stays a BRIDGING signal — it links
    same-cadence flows but never merges distinct agents alone.
    """
    explicit = _coerce_str(_dig(record, ("cadence_sig",), ("cadence",)))
    if explicit:
        return explicit if explicit.startswith("cad:") else f"cad:{explicit}"

    series = _coerce_float_list(
        _dig(record, ("inter_arrival_ms",), ("inter_arrivals",), ("iat_ms",))
    )
    if len(series) < 2:
        return None

    mean = sum(series) / len(series)
    # Rate band from the mean inter-arrival.
    if mean <= 100.0:
        rate = "fast"
    elif mean <= 2000.0:
        rate = "mid"
    else:
        rate = "slow"

    # Burstiness = normalized Shannon entropy of the inter-arrival histogram.
    # Low entropy ⇒ periodic (machine cron); high entropy ⇒ bursty (interactive).
    burst = _burstiness_band(series)
    return f"cad:{rate}:{burst}"


def _burstiness_band(series: Sequence[float]) -> str:
    """Coarse burstiness band of an inter-arrival series.

    The primary signal is the coefficient of variation (CV = stddev / mean): a
    cron/poll loop fires on a near-fixed period (CV≈0 ⇒ ``periodic``) regardless
    of the loop's absolute rate, while interactive/human-paced traffic has a high
    CV (irregular gaps ⇒ ``bursty``). CV is scale-free, so a tight 1-second loop
    reads periodic even though its absolute jitter is non-zero — which a
    range-based binning would mis-read as spread-out.

    The normalized Shannon entropy of the inter-arrival histogram is used as a
    secondary tie-breaker for the middle band.
    """
    if len(series) < 2:
        return "periodic"
    mean = sum(series) / len(series)
    if mean <= 0:
        return "periodic"
    var = sum((v - mean) ** 2 for v in series) / len(series)
    cv = math.sqrt(var) / mean
    if cv < 0.15:
        return "periodic"  # near-fixed period = a machine loop
    if cv >= 0.6:
        return "bursty"  # highly irregular = interactive / human-paced

    # Middle band: break the tie with the histogram entropy.
    lo, hi = min(series), max(series)
    if hi - lo < 1e-9:
        return "periodic"
    bins = 10
    counts = [0] * bins
    for v in series:
        idx = int((v - lo) / (hi - lo) * (bins - 1))
        counts[min(bins - 1, max(0, idx))] += 1
    total = sum(counts)
    entropy = -sum((c / total) * math.log2(c / total) for c in counts if c)
    norm = entropy / math.log2(bins)
    return "periodic" if norm < 0.33 else "mixed"


def parse_ocsf_flow_records(
    records: Iterable[Mapping[str, Any]]
) -> list[FlowFeatures]:
    """Parse raw OCSF/Zeek-style flow records into normalized ``FlowFeatures``.

    The REAL parser used by both the live feed and the labeled local shim. Reads
    the OCSF Network-Activity nested shape, the Zeek ssl.log flat shape, and a
    forward-proxy flat shape off the same record (``_dig`` aliases the paths).
    Derives the behavioral ``token_waveform_sig`` / ``cadence_sig`` /
    ``packetization_mode`` from explicit fields or from raw series. Drops a
    record only if it cannot be turned into a dict-shaped flow; a record with
    missing facets keeps the facets it has. Never raises.
    """
    out: list[FlowFeatures] = []
    for i, record in enumerate(records):
        if not isinstance(record, Mapping):
            continue
        dst = _extract_dst_name(record)
        provider = provider_for_host(dst) if dst else None
        waveform_sig, packetization = _quantize_waveform(record)
        cadence_sig = _quantize_cadence(record)
        ref = _coerce_str(_dig(record, ("evidence_ref",), ("uid",), ("flow_id",)))
        out.append(
            FlowFeatures(
                source_workload=_coerce_str(
                    _dig(
                        record,
                        ("source_workload",),
                        ("src_endpoint", "hostname"),
                        ("src_endpoint", "ip"),
                        ("src_ip",),
                        ("client",),
                    )
                ),
                ja4=_coerce_str(_dig(record, ("ja4",), ("tls", "ja4"), ("ja3",), ("tls", "ja3"))),
                ja4s=_coerce_str(_dig(record, ("ja4s",), ("tls", "ja4s"), ("ja3s",))),
                sni=dst,
                asn=_coerce_str(
                    _dig(record, ("asn",), ("dst_endpoint", "autonomous_system", "number"))
                ),
                egress_ip=_coerce_str(
                    _dig(record, ("egress_ip",), ("dst_endpoint", "ip"), ("dst_ip",))
                ),
                h2_settings_hash=_coerce_str(
                    _dig(
                        record,
                        ("h2_settings_hash",),
                        ("http2_fingerprint",),
                        ("http", "h2_fingerprint"),
                    )
                ),
                alpn=_coerce_str(_dig(record, ("alpn",), ("tls", "alpn"))),
                provider=provider,
                token_waveform_sig=waveform_sig,
                cadence_sig=cadence_sig,
                packetization_mode=packetization,
                connection_count=_coerce_int(
                    _dig(record, ("connection_count",), ("conn_count",)), default=1
                ),
                byte_total=_coerce_int(
                    _dig(record, ("bytes_out",), ("byte_total",), ("dst_bytes",)),
                    default=0,
                ),
                first_seen=_parse_iso(_dig(record, ("first_seen",), ("start_time",))),
                last_seen=_parse_iso(_dig(record, ("last_seen",), ("end_time",))),
                evidence_ref=ref or f"flow#{i}",
            )
        )
    return out


# ---------------------------------------------------------------------------
# Grouping → one entity-candidate footprint per distinct egress behavior
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class EgressGroup:
    """Aggregated flows sharing one behavioral egress fingerprint.

    The grouping key is the behavioral tuple that makes two flows the SAME
    candidate: ``(source_workload, ja4, sni, token_waveform_sig, cadence_sig)``.
    Crucially the behavioral axis is IN the key, so two agents behind one egress
    (same workload/ja4/sni) that differ in waveform or cadence resolve to TWO
    groups — the split the old stub (keyed only on workload/ja4/sni) could not
    make.
    """

    source_workload: str | None
    ja4: str | None
    sni: str | None
    provider: str | None
    token_waveform_sig: str | None
    cadence_sig: str | None
    packetization_mode: str | None
    ja4s: str | None
    asn: str | None
    egress_ip: str | None
    h2_settings_hash: str | None
    alpn: str | None
    connection_count: int
    byte_total: int
    flow_count: int
    first_seen: datetime | None
    last_seen: datetime | None
    evidence_ref: str


def group_flows(features: Sequence[FlowFeatures]) -> list[EgressGroup]:
    """Group parsed flows into behavioral egress candidates.

    Only flows whose destination resolves to a model/agent/MCP endpoint are kept
    (non-model egress is not agent evidence). Flows are grouped on the behavioral
    key so distinct agents behind one egress are separated. Returns a stable,
    deterministically-ordered list.
    """
    buckets: dict[tuple, list[FlowFeatures]] = defaultdict(list)
    for f in features:
        if f.provider is None:
            continue  # only model-endpoint egress is agent evidence
        key = (
            f.source_workload,
            f.ja4,
            f.sni,
            f.token_waveform_sig,
            f.cadence_sig,
        )
        buckets[key].append(f)

    groups: list[EgressGroup] = []
    for key, flows in buckets.items():
        firsts = [x.first_seen for x in flows if x.first_seen]
        lasts = [x.last_seen for x in flows if x.last_seen]
        groups.append(
            EgressGroup(
                source_workload=key[0],
                ja4=key[1],
                sni=key[2],
                provider=flows[0].provider,
                token_waveform_sig=key[3],
                cadence_sig=key[4],
                packetization_mode=_first_present(f.packetization_mode for f in flows),
                ja4s=_first_present(f.ja4s for f in flows),
                asn=_first_present(f.asn for f in flows),
                egress_ip=_first_present(f.egress_ip for f in flows),
                h2_settings_hash=_first_present(f.h2_settings_hash for f in flows),
                alpn=_first_present(f.alpn for f in flows),
                connection_count=sum(x.connection_count for x in flows),
                byte_total=sum(x.byte_total for x in flows),
                flow_count=len(flows),
                first_seen=min(firsts) if firsts else None,
                last_seen=max(lasts) if lasts else (min(firsts) if firsts else None),
                evidence_ref=sorted(x.evidence_ref for x in flows)[0],
            )
        )
    # Deterministic order for stable receipts / tests.
    groups.sort(key=lambda g: (str(g.source_workload), str(g.ja4), str(g.sni), str(g.token_waveform_sig)))
    return groups


def _first_present(values: Iterable[Any]) -> Any | None:
    for v in values:
        if v not in (None, ""):
            return v
    return None


# ---------------------------------------------------------------------------
# The EngineSensor
# ---------------------------------------------------------------------------


class NetworkEgressSensor:
    """P1–P4 network-egress plane instrument: flow records → ``Incidence``.

    Construct with a ``FlowSource`` (the real feed wrapped in a callable, or the
    labeled ``LocalFlowFixtureSource`` shim, or ``StaticFlowSource`` for an
    injected list). ``sense`` parses the source's flow records, drops non-model
    egress, groups on the BEHAVIORAL key (so two agents behind one egress split),
    and emits one ``Incidence`` per group keyed on
    ``{ja4, ja4s, sni, asn, egress_ip, h2_settings_hash, token_waveform_sig,
    cadence_sig}``.

    Degrade-to-empty: a ``None``/empty source, an unreadable fixture, or no
    model-endpoint egress all yield an empty iterable. NEVER raises.
    """

    plane_id: PlaneId = PlaneId.NETWORK_EGRESS

    def __init__(
        self,
        source: FlowSource | None = None,
        *,
        catchability: float = NETWORK_EGRESS_CATCHABILITY,
    ) -> None:
        self._source = source
        self._catchability = catchability

    def sense(self, context: SenseContext) -> Iterable[Incidence]:
        return list(self._iter(context))

    # ------------------------------------------------------------------
    # internals
    # ------------------------------------------------------------------

    def _iter(self, context: SenseContext) -> Iterator[Incidence]:
        if self._source is None:
            return
        try:
            raw = self._source(context)
        except Exception:  # noqa: BLE001 — degrade-to-empty is the contract
            return
        if raw is None:
            return
        try:
            features = parse_ocsf_flow_records(raw)
        except Exception:  # noqa: BLE001
            return
        for group in group_flows(features):
            inc = self._group_to_incidence(group)
            if inc is not None:
                yield inc

    def _group_to_incidence(self, group: EgressGroup) -> Incidence | None:
        # Build the footprint keys (the fuse.py BRIDGING-grade names). Only
        # present facets are emitted (missing field = weight 0 in fuse). The
        # behavioral signatures are FIRST-CLASS keys so the resolver can use
        # them as the split-axis.
        keys: dict[str, str] = {}
        if group.ja4:
            keys[FootprintField.JA4.value] = group.ja4
        if group.ja4s:
            keys[FootprintField.JA4S.value] = group.ja4s
        if group.sni:
            keys[FootprintField.SNI.value] = group.sni
        if group.asn:
            keys[FootprintField.ASN.value] = group.asn
        if group.egress_ip:
            keys[FootprintField.EGRESS_IP.value] = group.egress_ip
        if group.h2_settings_hash:
            keys[FootprintField.H2_SETTINGS_HASH.value] = group.h2_settings_hash
        if group.token_waveform_sig:
            keys[FootprintField.TOKEN_WAVEFORM_SIG.value] = group.token_waveform_sig
        if group.cadence_sig:
            keys[FootprintField.CADENCE_SIG.value] = group.cadence_sig

        # A flow with no comparable key at all carries no fusion signal; drop it
        # rather than emit a keyless footprint that can never fuse.
        if not keys:
            return None

        attrs: dict[str, str] = {
            "model_provider": group.provider or "unknown",
            "connection_count": str(group.connection_count),
            "flow_count": str(group.flow_count),
            "byte_total": str(group.byte_total),
            "signal": "tls_egress_observation",
            "metadata_only": "true",
        }
        if group.source_workload:
            attrs["source_workload"] = group.source_workload
        if group.packetization_mode:
            attrs["packetization_mode"] = group.packetization_mode
        if group.alpn:
            attrs["alpn"] = group.alpn
        if group.last_seen:
            attrs["last_seen"] = group.last_seen.isoformat()

        footprint = FootprintVector.of(
            plane_id=PlaneId.NETWORK_EGRESS, keys=keys, attrs=attrs
        )
        observed_at = group.last_seen or group.first_seen or datetime.now(UTC)
        try:
            return Incidence(
                plane_id=PlaneId.NETWORK_EGRESS,
                footprint=footprint,
                catchability=self._catchability,
                admissibility=NETWORK_EGRESS_ADMISSIBILITY,
                raw_evidence_ref=group.evidence_ref,
                observed_at=observed_at,
            )
        except ValueError:
            return None


# ---------------------------------------------------------------------------
# Registry factory (flag-gated; degrade-to-empty)
# ---------------------------------------------------------------------------


def build_network_egress_sensor(env: Mapping[str, str]) -> NetworkEgressSensor:
    """Factory for the registry — builds a flag-gated, degrade-empty sensor.

    The registry only invokes this when ``TEX_SIEVE_P1_JA4`` is truthy. The
    sensor's flow source is the labeled local fixture shim when
    ``TEX_SIEVE_P1_FLOW_FIXTURE`` names a readable file; otherwise the sensor is
    built with NO source so it senses nothing (a live deployment replaces the
    source by re-registering with its real Zeek/OCSF feed wrapped as a
    ``FlowSource``). Never raises — a missing/unreadable fixture degrades the
    sensor to empty rather than crashing the factory.
    """
    fixture = env.get(NETWORK_EGRESS_FIXTURE_ENV)
    source: FlowSource | None = None
    if isinstance(fixture, str) and fixture.strip():
        source = LocalFlowFixtureSource(fixture_path=Path(fixture.strip()))
    return NetworkEgressSensor(source=source)


def register(env_flag: str = NETWORK_EGRESS_FLAG) -> None:
    """Register this plane's factory into the sensor registry.

    Idempotent and import-safe: a deployment / the integrator calls this to wire
    the real factory into ``PlaneId.NETWORK_EGRESS``'s roster slot (replacing the
    inert placeholder). Kept as an explicit call (not import-time side effect) so
    importing this module never mutates global state.
    """
    from tex.discovery.engine.sensors.registry import register_sensor

    register_sensor(
        PlaneId.NETWORK_EGRESS, build_network_egress_sensor, env_flag=env_flag
    )


__all__ = [
    "NetworkEgressSensor",
    "FlowFeatures",
    "FlowSource",
    "StaticFlowSource",
    "LocalFlowFixtureSource",
    "EgressGroup",
    "parse_ocsf_flow_records",
    "group_flows",
    "provider_for_host",
    "build_network_egress_sensor",
    "register",
    "NETWORK_EGRESS_CATCHABILITY",
    "NETWORK_EGRESS_FLAG",
    "NETWORK_EGRESS_FIXTURE_ENV",
]
