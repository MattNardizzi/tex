import React, { useMemo, useRef, useState } from "react";
import { X, Download, Copy, Check, Share2, Zap } from "lucide-react";
import { VERDICT_META, ASI_DISPLAY, ASI_COVERED_COUNT } from "../lib/rounds";
import { permitProximity } from "../lib/storage";

/*
  SHARE CARD — v5 "WORDLE GRID + DUEL LINK"
  ──────────────────────────────────────────
  The v4 ShareCard leaned on an SVG poster. Good for screenshots,
  bad for virality — SVGs don't post well inline on LinkedIn or X,
  and nobody wants to download+attach an image for a casual brag.

  v5 leads with a COPY-PASTEABLE TEXT GRID, same mechanic that made
  Wordle viral:

      TEX ARENA · Round 5 · The Director
      🟪🟪🟨⬛⬛⬛  73% past
      Caught: ASI01 · ASI09
      texaegis.com/arena

  The squares are the Pokédex — one per ASI category Tex covers,
  colored by whether it fired on this attack and how decisively.
  The viewer sees the grid on LinkedIn and doesn't know what the
  squares mean. That's the curiosity gap. They click.

  Also new in v5:
    • Duel link generator — "I got 73% on Round 5. Beat me."
      Creates a URL that drops the recipient into the exact round.
    • Three copy-to-clipboard targets: emoji grid (X/LinkedIn text),
      LinkedIn-optimized long post, and duel link.
    • SVG download preserved as a secondary option for people who
      want the poster for slides or a zine piece.
*/

export default function ShareCard({ decision, round, player, onClose }) {
  const [copied, setCopied] = useState("");
  const svgRef = useRef(null);

  // Dedupe ASI findings by short_code, preserving order.
  // NOTE: all useMemo calls must run in the same order on every render,
  // so we compute them against safe fallbacks when decision is null and
  // handle the null-check with an early return at the bottom.
  const uniqueAsi = useMemo(() => {
    if (!decision) return [];
    const findings = Array.isArray(decision.asi_findings)
      ? decision.asi_findings
      : [];
    const seen = new Set();
    const out = [];
    for (const f of findings) {
      if (!f.short_code || seen.has(f.short_code)) continue;
      seen.add(f.short_code);
      out.push(f);
    }
    return out;
  }, [decision]);

  // Build the emoji grid — the viral payload.
  const emojiGrid = useMemo(
    () => buildEmojiGrid(uniqueAsi, decision?.verdict),
    [uniqueAsi, decision]
  );

  const meta = decision
    ? VERDICT_META[decision.verdict] || VERDICT_META.ABSTAIN
    : VERDICT_META.ABSTAIN;
  const handle = player?.handle || "anonymous";
  const proximity = decision ? permitProximity(decision) : 0;
  const proximityPct = Math.round(proximity * 100);

  // Three canonical share strings.
  const gridText = useMemo(
    () =>
      decision
        ? buildGridText({ decision, round, player, proximityPct, emojiGrid, uniqueAsi })
        : "",
    [decision, round, player, proximityPct, emojiGrid, uniqueAsi]
  );
  const linkedinPost = useMemo(
    () =>
      decision
        ? buildLinkedInPost({ decision, round, player, proximityPct, uniqueAsi })
        : "",
    [decision, round, player, proximityPct, uniqueAsi]
  );
  const duelUrl = useMemo(
    () => (round ? buildDuelUrl(round, handle) : ""),
    [round, handle]
  );

  // Early return AFTER all hooks — maintains hook order stability.
  if (!decision || !round || !player) return null;

  const copyTo = async (key, text) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(key);
      setTimeout(() => setCopied(""), 1800);
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
      className="fixed inset-0 z-50 flex items-center justify-center p-3 sm:p-4 safe-top safe-bottom"
      onClick={onClose}
      role="dialog"
      aria-modal="true"
      style={{
        background: "radial-gradient(ellipse at center, rgba(6, 7, 20, 0.94) 0%, rgba(6, 7, 20, 0.98) 80%)",
        backdropFilter: "blur(16px)",
      }}
    >
      <div
        className="panel relative w-full max-w-[640px] max-h-[92vh] overflow-y-auto rise-in"
        onClick={(e) => e.stopPropagation()}
        style={{
          borderColor: "var(--color-cyan)",
          boxShadow:
            "0 24px 80px rgba(0, 0, 0, 0.6), 0 0 0 1px var(--color-cyan), 0 0 48px rgba(95, 240, 255, 0.3)",
        }}
      >
        {/* Header */}
        <div className="flex items-center justify-between px-5 py-3 border-b border-[var(--color-hairline-2)]">
          <div>
            <div className="t-micro text-[var(--color-cyan)]">
              Share your fight
            </div>
            <div className="t-display text-[22px] leading-none mt-1 text-[var(--color-ink)]">
              Post it. Challenge someone.
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 text-[var(--color-ink-dim)] hover:text-[var(--color-ink)] transition-colors"
            aria-label="Close"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* GRID PREVIEW — the primary artifact */}
        <div className="px-5 py-4 border-b border-[var(--color-hairline)]">
          <div className="flex items-center justify-between mb-2">
            <span className="t-micro text-[var(--color-violet)]">
              Emoji grid · the copy-paste brag
            </span>
            <span className="t-micro text-[var(--color-ink-faint)]">
              X · LinkedIn · Slack
            </span>
          </div>
          <div
            className="font-mono text-[13px] leading-[1.6] text-[var(--color-ink)] p-4 whitespace-pre-wrap border"
            style={{
              background: "var(--color-bg)",
              borderColor: "var(--color-hairline-2)",
              borderRadius: "2px",
            }}
          >
            {gridText}
          </div>
          <button
            onClick={() => copyTo("grid", gridText)}
            className="mt-2 w-full inline-flex items-center justify-center gap-2 py-2.5 transition-all"
            style={{
              background: "var(--color-violet)",
              color: "#fff",
              fontFamily: "var(--font-mono)",
              fontSize: "11px",
              fontWeight: 700,
              letterSpacing: "0.22em",
              textTransform: "uppercase",
              borderRadius: "2px",
              boxShadow: "0 0 20px rgba(168, 85, 247, 0.4)",
            }}
          >
            {copied === "grid" ? <Check className="w-4 h-4" /> : <Copy className="w-4 h-4" />}
            {copied === "grid" ? "Copied — go paste it" : "Copy grid"}
          </button>
        </div>

        {/* LinkedIn long-form post */}
        <details className="border-b border-[var(--color-hairline)] group">
          <summary className="px-5 py-3 flex items-center justify-between cursor-pointer list-none">
            <div className="inline-flex items-center gap-2">
              <Share2 className="w-3.5 h-3.5 text-[var(--color-cyan)]" />
              <span className="t-micro text-[var(--color-cyan)]">
                LinkedIn long-form post
              </span>
            </div>
            <span className="t-micro text-[var(--color-ink-faint)] group-open:rotate-180 transition-transform">
              ▾
            </span>
          </summary>
          <div className="px-5 pb-4">
            <div
              className="font-mono text-[11.5px] leading-[1.55] text-[var(--color-ink-dim)] p-3 whitespace-pre-wrap border max-h-[200px] overflow-y-auto"
              style={{
                background: "var(--color-bg)",
                borderColor: "var(--color-hairline)",
                borderRadius: "2px",
              }}
            >
              {linkedinPost}
            </div>
            <button
              onClick={() => copyTo("linkedin", linkedinPost)}
              className="mt-2 w-full inline-flex items-center justify-center gap-2 py-2 btn-ghost"
              style={{
                borderColor: "var(--color-cyan)",
                color: "var(--color-cyan)",
              }}
            >
              {copied === "linkedin" ? <Check className="w-4 h-4" /> : <Copy className="w-4 h-4" />}
              {copied === "linkedin" ? "Copied" : "Copy LinkedIn post"}
            </button>
          </div>
        </details>

        {/* Duel link */}
        <div className="px-5 py-4 border-b border-[var(--color-hairline)]">
          <div className="flex items-center justify-between mb-2">
            <span className="t-micro text-[var(--color-pink)]">
              ⚔ Duel link · drop a friend into this exact round
            </span>
          </div>
          <div
            className="font-mono text-[11.5px] text-[var(--color-cyan)] p-3 border overflow-x-auto no-scrollbar whitespace-nowrap"
            style={{
              background: "var(--color-bg)",
              borderColor: "var(--color-pink)",
              borderRadius: "2px",
            }}
          >
            {duelUrl}
          </div>
          <button
            onClick={() => copyTo("duel", duelUrl)}
            className="mt-2 w-full inline-flex items-center justify-center gap-2 py-2.5 transition-all btn-primary"
            style={{ fontSize: "14px", padding: "0.65rem 1rem" }}
          >
            {copied === "duel" ? <Check className="w-4 h-4" /> : <Zap className="w-4 h-4" strokeWidth={2.5} />}
            {copied === "duel" ? "Copied — send it" : `Challenge a friend on ${round.name}`}
          </button>
        </div>

        {/* SVG download (secondary) */}
        <details className="border-b border-[var(--color-hairline)] group">
          <summary className="px-5 py-3 flex items-center justify-between cursor-pointer list-none">
            <span className="t-micro text-[var(--color-ink-dim)]">
              Download poster (SVG)
            </span>
            <span className="t-micro text-[var(--color-ink-faint)] group-open:rotate-180 transition-transform">
              ▾
            </span>
          </summary>
          <div className="px-5 pb-4">
            <div className="border border-[var(--color-hairline)]">
              <ShareSvg
                ref={svgRef}
                decision={decision}
                round={round}
                handle={handle}
                meta={meta}
                uniqueAsi={uniqueAsi}
                proximityPct={proximityPct}
              />
            </div>
            <button
              onClick={handleDownload}
              className="mt-2 w-full inline-flex items-center justify-center gap-2 py-2 btn-ghost"
            >
              <Download className="w-4 h-4" />
              Download SVG
            </button>
          </div>
        </details>

        {/* Bottom action row */}
        <div className="px-5 py-3 text-center">
          <p
            className="text-[11px] italic text-[var(--color-ink-faint)]"
            style={{ fontFamily: "var(--font-serif)" }}
          >
            Every share recruits the next player. Seriously — that's the whole engine.
          </p>
        </div>
      </div>
    </div>
  );
}

/* ─────────────────────────────────────────────────────────────────── */
/*  buildEmojiGrid — the Wordle-style visual payload                   */
/*                                                                     */
/*  One square per ASI category Tex covers (6 total). Color mapping:   */
/*    🟥  DECISIVE (this category alone moved the verdict)              */
/*    🟨  CONTRIBUTING (fed the fused score)                            */
/*    🟪  INFORMATIONAL (fired weakly, surfaced for completeness)       */
/*    ⬛  did not fire                                                   */
/*    🟩  on a PERMIT (clean pass — you got through)                    */
/* ─────────────────────────────────────────────────────────────────── */

function buildEmojiGrid(uniqueAsi, verdict) {
  const CATS = Object.values(ASI_DISPLAY).map((c) => c.short);
  const byCode = {};
  uniqueAsi.forEach((f) => {
    byCode[f.short_code] = f.verdict_influence || "informational";
  });

  if (verdict === "PERMIT") {
    // Clean pass — all green. This is the flex post.
    return "🟩".repeat(CATS.length);
  }

  return CATS.map((code) => {
    const inf = byCode[code];
    if (!inf) return "⬛";
    if (inf === "decisive") return "🟥";
    if (inf === "contributing") return "🟨";
    return "🟪";
  }).join("");
}

/* ─────────────────────────────────────────────────────────────────── */
/*  Share text builders                                                 */
/* ─────────────────────────────────────────────────────────────────── */

function buildGridText({ decision, round, player, proximityPct, emojiGrid, uniqueAsi }) {
  const handle = player.handle ? `@${player.handle}` : "";
  const isWin = decision.verdict === "PERMIT";
  const isBounty = round.isBounty && isWin;

  const header = isBounty
    ? `TEX ARENA · ⚠ BOUNTY ROUND · ${round.name}`
    : `TEX ARENA · Round ${round.id} · ${round.name}`;

  const proxLine = isWin
    ? isBounty
      ? "🏆 BEAT THE WARDEN · Hall of Fame"
      : "✓ SLIPPED PAST"
    : `${proximityPct}% past`;

  const catLine =
    uniqueAsi.length > 0 && !isWin
      ? `Caught: ${uniqueAsi.map((f) => f.short_code).join(" · ")}`
      : isWin
      ? "Clean pass · 0 ASI categories fired"
      : "";

  return [
    header,
    `${emojiGrid}  ${proxLine}`,
    catLine,
    handle,
    "texaegis.com/arena",
  ]
    .filter(Boolean)
    .join("\n");
}

function buildLinkedInPost({ decision, round, player, proximityPct, uniqueAsi }) {
  const handle = player.handle ? `@${player.handle}` : "";
  const isWin = decision.verdict === "PERMIT";
  const isBounty = round.isBounty && isWin;

  if (isBounty) {
    return `Beat THE WARDEN on Tex Arena.

Tex is a content gate for AI agents — it inspects agent outputs BEFORE they execute and returns PERMIT / ABSTAIN / FORBID with full evidence chains, mapped to OWASP ASI 2026.

Round 7 runs the strict policy. Getting a genuinely harmful payload past it → Hall of Fame + Founding Bypass certificate + API access.

Try it yourself → texaegis.com/arena

${handle}`;
  }

  if (isWin) {
    return `Just beat Round ${round.id} ("${round.name}") on Tex Arena — an OWASP ASI 2026 red-team challenge against an AI content gate.

Got ${proximityPct}% past the policy. Round 7 (The Warden) is still unbeaten though — Hall of Fame is still empty.

Every round is mapped to a real agent risk category. Every loss teaches you one. Worth 5 minutes if you're building agents.

texaegis.com/arena

${handle}`;
  }

  // FORBID / ABSTAIN
  const caught =
    uniqueAsi.length > 0
      ? `\n\nTex caught: ${uniqueAsi
          .slice(0, 3)
          .map((f) => `${f.short_code} (${ASI_DISPLAY[f.short_code]?.title || ""})`)
          .join(" · ")}`
      : "";

  return `Ran an adversarial attack against Tex, an AI content gate that evaluates agent outputs against OWASP ASI 2026 categories.

Round ${round.id} · ${round.name} · got ${proximityPct}% past the policy.${caught}

This is what agent content evaluation actually looks like — structured findings, sub-2ms verdicts, hash-chained evidence. Try it yourself, it's free.

texaegis.com/arena

${handle}`;
}

function buildDuelUrl(round, handle) {
  // Duel URL is parsed by App.jsx on load — see useEffect in App.jsx
  // Format: texaegis.com/arena?duel=5&from=mhwall
  const base = "https://texaegis.com/arena";
  const params = new URLSearchParams();
  params.set("duel", String(round.id));
  if (handle && handle !== "anonymous") params.set("from", handle);
  return `${base}?${params.toString()}`;
}

/* ─────────────────────────────────────────────────────────────────── */
/*  SVG — kept as secondary download. Updated palette to match v5     */
/*  (dark indigo + cyan), but layout is unchanged.                    */
/* ─────────────────────────────────────────────────────────────────── */

const ShareSvg = React.forwardRef(function ShareSvg(
  { decision, round, handle, meta, uniqueAsi, proximityPct },
  ref
) {
  const W = 1200;
  const H = 630;
  const colors = {
    bg: "#060714",
    bg2: "#0c0e22",
    ink: "#f5f7ff",
    inkDim: "#b8bce0",
    inkFaint: "#5a608c",
    pink: "#ff3d7a",
    cyan: "#5ff0ff",
    yellow: "#ffe14a",
    violet: "#a855f7",
    permit: "#3bff9e",
    red: "#ff3b3b",
  };
  const isWin = decision.verdict === "PERMIT";
  const isBounty = round.isBounty && isWin;
  const accent = isBounty
    ? colors.yellow
    : isWin
    ? colors.permit
    : decision.verdict === "ABSTAIN"
    ? colors.yellow
    : colors.pink;

  const verdictWord = isBounty
    ? "BELT CLAIMED"
    : isWin
    ? "SLIPPED PAST"
    : decision.verdict === "ABSTAIN"
    ? "ESCALATED"
    : "BLOCKED";

  return (
    <svg
      ref={ref}
      viewBox={`0 0 ${W} ${H}`}
      width="100%"
      xmlns="http://www.w3.org/2000/svg"
      style={{ display: "block", background: colors.bg }}
    >
      {/* Background gradient */}
      <defs>
        <linearGradient id="bg-grad" x1="0" x2="1" y1="0" y2="1">
          <stop offset="0%" stopColor="#0a0d28" />
          <stop offset="100%" stopColor="#040612" />
        </linearGradient>
        <radialGradient id="glow-accent" cx="50%" cy="50%" r="50%">
          <stop offset="0%" stopColor={accent} stopOpacity="0.25" />
          <stop offset="100%" stopColor={accent} stopOpacity="0" />
        </radialGradient>
      </defs>
      <rect x="0" y="0" width={W} height={H} fill="url(#bg-grad)" />
      <rect x="0" y="0" width={W} height={H} fill="url(#glow-accent)" />

      {/* Border */}
      <rect
        x="8"
        y="8"
        width={W - 16}
        height={H - 16}
        fill="none"
        stroke={accent}
        strokeWidth="2"
        opacity="0.6"
      />

      {/* Header strip */}
      <text
        x="50"
        y="55"
        fontFamily="JetBrains Mono, monospace"
        fontSize="14"
        fill={colors.cyan}
        letterSpacing="4"
      >
        TEX ARENA · ROUND {round.id} · {round.name.toUpperCase()}
      </text>

      {/* Verdict — huge */}
      <text
        x="50"
        y="200"
        fontFamily="Anton, Impact, sans-serif"
        fontSize="140"
        fontWeight="400"
        fill={colors.ink}
        letterSpacing="-2"
      >
        {verdictWord}.
      </text>

      {/* Proximity pct */}
      <text
        x="50"
        y="280"
        fontFamily="JetBrains Mono, monospace"
        fontSize="20"
        fill={colors.inkDim}
        letterSpacing="3"
      >
        {isWin ? "VERDICT" : "HOW CLOSE"}
      </text>
      <text
        x="50"
        y="360"
        fontFamily="Anton, Impact, sans-serif"
        fontSize="96"
        fill={accent}
        letterSpacing="-1"
      >
        {isWin ? "PERMIT" : `${proximityPct}%`}
      </text>

      {/* ASI chips */}
      {uniqueAsi.slice(0, 3).map((f, i) => (
        <AsiChip
          key={f.short_code + i}
          x={W - 420}
          y={120 + i * 92}
          code={f.short_code}
          title={ASI_DISPLAY[f.short_code]?.title || f.title || ""}
          influence={f.verdict_influence}
          colors={colors}
        />
      ))}
      {isWin && uniqueAsi.length === 0 && (
        <g>
          <text
            x={W - 420}
            y="160"
            fontFamily="JetBrains Mono, monospace"
            fontSize="12"
            fill={colors.permit}
            letterSpacing="3"
          >
            CLEAN PASS
          </text>
          <text
            x={W - 420}
            y="200"
            fontFamily="Instrument Serif, serif"
            fontSize="26"
            fontStyle="italic"
            fill={colors.inkDim}
          >
            0 ASI categories fired.
          </text>
        </g>
      )}

      {/* Footer */}
      <line
        x1="50"
        y1={H - 90}
        x2={W - 50}
        y2={H - 90}
        stroke={colors.cyan}
        strokeOpacity="0.35"
        strokeWidth="1"
      />
      <text
        x="50"
        y={H - 42}
        fontFamily="JetBrains Mono, monospace"
        fontSize="14"
        fill={colors.ink}
        letterSpacing="3"
      >
        @{handle.toUpperCase()} · TEXAEGIS.COM/ARENA
      </text>
      <text
        x={W - 50}
        y={H - 42}
        textAnchor="end"
        fontFamily="Instrument Serif, serif"
        fontSize="22"
        fontStyle="italic"
        fill={colors.cyan}
        opacity="0.85"
      >
        can you beat the gate?
      </text>
    </svg>
  );
});

function AsiChip({ x, y, code, title, influence, colors }) {
  const influenceColor =
    influence === "decisive"
      ? colors.red
      : influence === "contributing"
      ? colors.yellow
      : colors.cyan;

  return (
    <g transform={`translate(${x}, ${y})`}>
      <rect
        x="0"
        y="0"
        width="380"
        height="76"
        fill={colors.bg2}
        stroke={influenceColor}
        strokeWidth="1.5"
        opacity="0.9"
      />
      <rect x="0" y="0" width="6" height="76" fill={influenceColor} />
      <text
        x="22"
        y="34"
        fontFamily="JetBrains Mono, monospace"
        fontSize="22"
        fontWeight="700"
        fill={colors.ink}
        letterSpacing="0"
      >
        {code}
      </text>
      <text
        x="22"
        y="58"
        fontFamily="Instrument Serif, serif"
        fontSize="18"
        fontStyle="italic"
        fill={colors.inkDim}
      >
        {title}
      </text>
      <text
        x="360"
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
