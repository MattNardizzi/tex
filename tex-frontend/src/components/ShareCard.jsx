import React, { useRef, useState, useMemo } from "react";
import { X, Download, Copy, Check } from "lucide-react";
import { VERDICT_META, ASI_DISPLAY } from "../lib/rounds";

export default function ShareCard({ decision, round, player, onClose }) {
  const [copied, setCopied] = useState(false);
  const svgRef = useRef(null);

  if (!decision) return null;

  const meta = VERDICT_META[decision.verdict] || VERDICT_META.ABSTAIN;
  const handle = player.handle || "anonymous";

  // Dedupe ASI findings by short_code for the share card — the image
  // has finite real estate, and we want to tell the "X categories
  // caught me" story, not list ten near-duplicates.
  const uniqueAsi = useMemo(() => {
    const findings = Array.isArray(decision.asi_findings)
      ? decision.asi_findings
      : [];
    const seen = new Set();
    const out = [];
    for (const f of findings) {
      if (!f.short_code || seen.has(f.short_code)) continue;
      seen.add(f.short_code);
      out.push(f);
      if (out.length >= 3) break;
    }
    return out;
  }, [decision]);

  const tweet = buildTweet({ decision, round, player, uniqueAsi });

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(tweet);
      setCopied(true);
      setTimeout(() => setCopied(false), 1800);
    } catch {}
  };

  const handleDownload = () => {
    const svg = svgRef.current;
    if (!svg) return;
    const serializer = new XMLSerializer();
    const source = serializer.serializeToString(svg);
    const blob = new Blob(
      ['<?xml version="1.0" standalone="no"?>\r\n', source],
      { type: "image/svg+xml;charset=utf-8" }
    );
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = `tex-arena-r${round.id}-${decision.verdict.toLowerCase()}.svg`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  };

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-ink/70 backdrop-blur-sm"
      onClick={onClose}
    >
      <div
        className="relative w-full max-w-[760px] bg-paper border-2 border-ink ink-shadow max-h-[92vh] overflow-y-auto"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Header */}
        <div className="flex items-center justify-between px-5 py-3 border-b-2 border-ink bg-ink text-paper">
          <div>
            <div className="font-mono text-[10px] uppercase tracking-[0.28em] text-paper-dim">
              Share your fight
            </div>
            <div className="font-display font-black text-[18px] leading-none mt-0.5">
              Attack card
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 hover:bg-paper/10 rounded-full"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* SVG preview */}
        <div className="p-5 bg-paper-dim">
          <div className="border-2 border-ink">
            <ShareSvg
              ref={svgRef}
              decision={decision}
              round={round}
              handle={handle}
              meta={meta}
              uniqueAsi={uniqueAsi}
            />
          </div>
        </div>

        {/* Pre-written post */}
        <div className="px-5 py-4 border-t-2 border-ink">
          <div className="font-mono text-[10px] uppercase tracking-[0.26em] text-ink-mid mb-2">
            Suggested post
          </div>
          <div className="font-mono text-[12px] leading-[1.55] text-ink bg-paper-dim border border-ink/20 p-3 whitespace-pre-wrap">
            {tweet}
          </div>
        </div>

        {/* Actions */}
        <div className="grid grid-cols-2 divide-x-2 divide-ink border-t-2 border-ink">
          <button
            onClick={handleCopy}
            className="flex items-center justify-center gap-2 py-3.5 bg-paper hover:bg-ink hover:text-paper transition-colors font-mono text-[11px] uppercase tracking-[0.22em] font-bold"
          >
            {copied ? (
              <>
                <Check className="w-3.5 h-3.5" />
                Copied
              </>
            ) : (
              <>
                <Copy className="w-3.5 h-3.5" />
                Copy post
              </>
            )}
          </button>
          <button
            onClick={handleDownload}
            className="flex items-center justify-center gap-2 py-3.5 bg-signal text-paper hover:bg-signal-deep transition-colors font-mono text-[11px] uppercase tracking-[0.22em] font-bold"
          >
            <Download className="w-3.5 h-3.5" />
            Download card
          </button>
        </div>
      </div>
    </div>
  );
}

function buildTweet({ decision, round, player, uniqueAsi }) {
  const handle = player.handle ? `@${player.handle} ` : "";
  const asiLine =
    uniqueAsi.length > 0
      ? `\n\nTex caught: ${uniqueAsi
          .map((f) => `${f.short_code} ${asiTitle(f)}`)
          .join(" · ")}`
      : "";

  if (decision.verdict === "PERMIT") {
    if (round.isBounty) {
      return `${handle}I just beat THE WARDEN in TEX Arena — Round 7, the bounty round.\n\nI got a payload past an AI content gate running OWASP ASI 2026 coverage live. $10 Starbucks incoming?\n\ntexaegis.com`;
    }
    return `${handle}I beat Round ${round.id} of TEX Arena — "${round.name}".\n\nI slipped a payload past an AI content gate. Round 7 is still standing, though.\n\nCan you beat Tex? texaegis.com`;
  }

  if (decision.verdict === "ABSTAIN") {
    return `${handle}took Round ${round.id} — "${round.name}" — to a draw.${asiLine}\n\nTex escalated my content for human review instead of blocking it. Close, but no point.\n\ntexaegis.com`;
  }

  // FORBID
  return `${handle}I got blocked by Tex on Round ${round.id} — "${round.name}".${asiLine}\n\nStructured OWASP ASI 2026 findings. Counterfactuals. Hash-chained evidence bundle. This is what agent content evaluation looks like.\n\ntexaegis.com`;
}

function asiTitle(finding) {
  const meta = ASI_DISPLAY[finding.short_code];
  if (meta) return meta.title;
  return finding.title || "";
}

// ─────────────────────────────────────────────────────────────────────
//  SVG card — what gets downloaded / screenshotted
// ─────────────────────────────────────────────────────────────────────

const ShareSvg = React.forwardRef(function ShareSvg(
  { decision, round, handle, meta, uniqueAsi },
  ref
) {
  const W = 1200;
  const H = 630;
  const colors = {
    paper: "#f5f0e6",
    ink: "#0c0a09",
    signal: "#e85d3c",
    permit: "#3b7a57",
    review: "#c78a2e",
  };
  const accent =
    meta.tone === "permit"
      ? colors.permit
      : meta.tone === "review"
      ? colors.review
      : colors.signal;

  const hasAsi = uniqueAsi.length > 0;

  return (
    <svg
      ref={ref}
      viewBox={`0 0 ${W} ${H}`}
      xmlns="http://www.w3.org/2000/svg"
      style={{ width: "100%", height: "auto", display: "block" }}
    >
      <rect width={W} height={H} fill={colors.paper} />

      <defs>
        <pattern id="grid" width="32" height="32" patternUnits="userSpaceOnUse">
          <path
            d="M 32 0 L 0 0 0 32"
            fill="none"
            stroke={colors.ink}
            strokeOpacity="0.05"
            strokeWidth="1"
          />
        </pattern>
        <pattern
          id="stripe"
          patternUnits="userSpaceOnUse"
          width="12"
          height="12"
          patternTransform="rotate(45)"
        >
          <rect width="2" height="12" fill={colors.ink} />
        </pattern>
      </defs>
      <rect width={W} height={H} fill="url(#grid)" />

      <rect
        x="20"
        y="20"
        width={W - 40}
        height={H - 40}
        fill="none"
        stroke={colors.ink}
        strokeWidth="4"
      />
      <rect x="20" y="20" width={W - 40} height="18" fill="url(#stripe)" opacity="0.65" />

      {/* Header row */}
      <text
        x="50"
        y="78"
        fontFamily="JetBrains Mono, monospace"
        fontSize="15"
        fill={colors.ink}
        letterSpacing="4"
        fontWeight="600"
      >
        TEX ARENA · ROUND {round.id} · {round.difficulty.toUpperCase()} · OWASP ASI 2026
      </text>

      {/* Round name + tagline */}
      <text
        x="50"
        y="155"
        fontFamily="Fraunces, serif"
        fontSize="68"
        fontWeight="900"
        fill={colors.ink}
        letterSpacing="-1.5"
      >
        {round.name}
      </text>
      <text
        x="50"
        y="192"
        fontFamily="Instrument Serif, serif"
        fontSize="26"
        fontStyle="italic"
        fill={accent}
      >
        {round.tagline}
      </text>

      <line
        x1="50"
        y1="218"
        x2={W - 50}
        y2="218"
        stroke={colors.ink}
        strokeOpacity="0.25"
        strokeWidth="2"
      />

      {/* Verdict block — shortened to make room for ASI strip */}
      <rect x="50" y="238" width={W - 100} height="148" fill={accent} />
      <rect x="50" y="238" width={W - 100} height="148" fill="url(#stripe)" opacity="0.09" />

      <text
        x="75"
        y="275"
        fontFamily="JetBrains Mono, monospace"
        fontSize="13"
        fill={colors.paper}
        letterSpacing="4"
        opacity="0.9"
      >
        VERDICT
      </text>
      <text
        x="75"
        y="360"
        fontFamily="Fraunces, serif"
        fontSize="84"
        fontWeight="900"
        fill={meta.tone === "review" ? colors.ink : colors.paper}
        letterSpacing="-2"
      >
        {meta.outcome}
      </text>

      <text
        x={W - 75}
        y="275"
        textAnchor="end"
        fontFamily="JetBrains Mono, monospace"
        fontSize="13"
        fill={colors.paper}
        letterSpacing="4"
        opacity="0.9"
      >
        TEX RETURNED
      </text>
      <text
        x={W - 75}
        y="360"
        textAnchor="end"
        fontFamily="Fraunces, serif"
        fontSize="68"
        fontWeight="800"
        fill={meta.tone === "review" ? colors.ink : colors.paper}
        letterSpacing="1"
      >
        {meta.short}
      </text>

      {/* ASI strip — the centerpiece of the share card when findings fired */}
      {hasAsi && (
        <g transform="translate(50, 410)">
          <text
            x="0"
            y="0"
            fontFamily="JetBrains Mono, monospace"
            fontSize="13"
            fill={colors.ink}
            letterSpacing="4"
            opacity="0.75"
          >
            TEX CAUGHT
          </text>
          {uniqueAsi.map((f, i) => (
            <AsiChip
              key={i}
              x={i * 360}
              y={18}
              code={f.short_code}
              title={asiTitle(f)}
              influence={f.verdict_influence}
              colors={colors}
            />
          ))}
        </g>
      )}

      {/* Score strip */}
      <g transform={`translate(50, ${hasAsi ? 515 : 475})`}>
        <ScoreBlock
          x={0}
          label="FINAL"
          value={decision.final_score.toFixed(2)}
          colors={colors}
        />
        <ScoreBlock
          x={260}
          label="CONFIDENCE"
          value={`${Math.round(decision.confidence * 100)}%`}
          colors={colors}
        />
        <ScoreBlock
          x={520}
          label="LATENCY"
          value={
            decision.latency
              ? `${decision.latency.total_ms.toFixed(1)}ms`
              : `${decision.elapsed_ms}ms`
          }
          colors={colors}
        />
        <ScoreBlock
          x={780}
          label="POLICY"
          value={decision.policy_version}
          colors={colors}
          small
        />
      </g>

      {/* Footer */}
      <line
        x1="50"
        y1={H - 62}
        x2={W - 50}
        y2={H - 62}
        stroke={colors.ink}
        strokeOpacity="0.25"
        strokeWidth="2"
      />
      <text
        x="50"
        y={H - 32}
        fontFamily="JetBrains Mono, monospace"
        fontSize="13"
        fill={colors.ink}
        letterSpacing="3"
      >
        @{handle.toUpperCase()} · TEXAEGIS.COM
      </text>
      <text
        x={W - 50}
        y={H - 32}
        textAnchor="end"
        fontFamily="Instrument Serif, serif"
        fontSize="18"
        fontStyle="italic"
        fill={colors.ink}
        opacity="0.75"
      >
        can you beat the gate?
      </text>
    </svg>
  );
});

function AsiChip({ x, y, code, title, influence, colors }) {
  const influenceColor =
    influence === "decisive"
      ? colors.signal
      : influence === "contributing"
      ? colors.review
      : colors.ink;

  return (
    <g transform={`translate(${x}, ${y})`}>
      <rect
        x="0"
        y="0"
        width="340"
        height="72"
        fill={colors.paper}
        stroke={colors.ink}
        strokeWidth="2"
      />
      <rect x="0" y="0" width="6" height="72" fill={influenceColor} />
      <text
        x="20"
        y="32"
        fontFamily="Fraunces, serif"
        fontSize="22"
        fontWeight="900"
        fill={colors.ink}
        letterSpacing="-0.5"
      >
        {code}
      </text>
      <text
        x="20"
        y="54"
        fontFamily="Instrument Serif, serif"
        fontSize="18"
        fontStyle="italic"
        fill={colors.ink}
        opacity="0.8"
      >
        {title}
      </text>
      <text
        x="320"
        y="30"
        textAnchor="end"
        fontFamily="JetBrains Mono, monospace"
        fontSize="9"
        fill={influenceColor}
        letterSpacing="2"
        fontWeight="700"
      >
        {(influence || "").toUpperCase()}
      </text>
    </g>
  );
}

function ScoreBlock({ x, label, value, colors, small }) {
  return (
    <g transform={`translate(${x}, 0)`}>
      <text
        x="0"
        y="0"
        fontFamily="JetBrains Mono, monospace"
        fontSize="11"
        fill={colors.ink}
        opacity="0.6"
        letterSpacing="3"
      >
        {label}
      </text>
      <text
        x="0"
        y="42"
        fontFamily={small ? "JetBrains Mono, monospace" : "Fraunces, serif"}
        fontSize={small ? "20" : "40"}
        fontWeight="900"
        fill={colors.ink}
      >
        {value}
      </text>
    </g>
  );
}
