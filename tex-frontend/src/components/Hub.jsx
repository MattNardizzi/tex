import React, { useEffect, useMemo, useRef, useState } from "react";
import { clickSfx } from "../lib/sounds.js";
import {
  getDailyLeaderboard,
  getHandle,
} from "../lib/leaderboard.js";
import { todayKey } from "../lib/dailyShift.js";

/*
  Hub v14 — Master cinematic landing
  ──────────────────────────────────
  The first impression. Single hero composition; no boot sequence noise.

  Layout (desktop):
    ┌──────────────────────────────────────────────────────────────┐
    │  TOP STATUS BAR (build / online ops / breach counter / time) │
    ├──────────────────────────────────────────────────────────────┤
    │                                                              │
    │   [HEADLINE]                              [TEX AVATAR]       │
    │   THE GATE                                + heart-pulse hex  │
    │   BETWEEN AI                              + eye scan         │
    │   AND THE                                 + corner badges    │
    │   REAL WORLD.                             + rt tickers       │
    │                                                              │
    │   [sub copy + CTAs]                                          │
    │                                                              │
    │   [demo ticker — live verdicts streaming]                    │
    ├──────────────────────────────────────────────────────────────┤
    │  ANATOMY STRIP (3 columns: WATCHES / VERDICTS / RECEIPTS)    │
    ├──────────────────────────────────────────────────────────────┤
    │  LEADERBOARD — TOP 8 today                                   │
    │  + mini-rules footer                                         │
    └──────────────────────────────────────────────────────────────┘

  Layered atmosphere: drifting particles, grid, haze, scanline overlay.
  THexSvg is exported for reuse by Game.jsx and WhatIsTex.jsx.
*/

// ── Tex hex glyph ──────────────────────────────────────────────────────
export function THexSvg({ className = "", title = "T" }) {
  return (
    <svg viewBox="0 0 100 115" className={className} aria-hidden={!title}>
      {title ? <title>{title}</title> : null}
      <defs>
        <linearGradient id="thex-grad" x1="0%" y1="0%" x2="100%" y2="100%">
          <stop offset="0%" stopColor="var(--pink)" stopOpacity="0.95" />
          <stop offset="55%" stopColor="var(--pink-hot)" stopOpacity="1" />
          <stop offset="100%" stopColor="var(--cyan)" stopOpacity="0.85" />
        </linearGradient>
        <filter id="thex-glow" x="-30%" y="-30%" width="160%" height="160%">
          <feGaussianBlur stdDeviation="2.4" />
          <feMerge>
            <feMergeNode />
            <feMergeNode in="SourceGraphic" />
          </feMerge>
        </filter>
      </defs>
      {/* outer hex */}
      <polygon
        points="50,3 95,28 95,87 50,112 5,87 5,28"
        fill="none"
        stroke="url(#thex-grad)"
        strokeWidth="2.5"
        filter="url(#thex-glow)"
      />
      {/* inner hex */}
      <polygon
        points="50,18 80,35 80,80 50,97 20,80 20,35"
        fill="none"
        stroke="var(--pink-hot)"
        strokeWidth="1.4"
        opacity="0.85"
      />
      {/* T mark */}
      <g stroke="url(#thex-grad)" strokeWidth="3" strokeLinecap="round" filter="url(#thex-glow)">
        <line x1="32" y1="40" x2="68" y2="40" />
        <line x1="50" y1="40" x2="50" y2="78" />
      </g>
      {/* tiny corner ticks */}
      <g fill="var(--pink-hot)" opacity="0.9">
        <circle cx="50" cy="3" r="1.6" />
        <circle cx="95" cy="28" r="1.4" />
        <circle cx="95" cy="87" r="1.4" />
        <circle cx="50" cy="112" r="1.6" />
        <circle cx="5" cy="87" r="1.4" />
        <circle cx="5" cy="28" r="1.4" />
      </g>
    </svg>
  );
}

// ── Ambient particles drifting up the screen ───────────────────────────
function AmbientParticles({ count = 32 }) {
  const particles = useMemo(() => {
    const arr = [];
    for (let i = 0; i < count; i++) {
      arr.push({
        id: i,
        left: Math.random() * 100,
        delay: Math.random() * 18,
        duration: 14 + Math.random() * 16,
        opacity: 0.25 + Math.random() * 0.5,
        scale: 0.6 + Math.random() * 1.4,
      });
    }
    return arr;
  }, [count]);
  return (
    <div className="hub-particles" aria-hidden="true">
      {particles.map((p) => (
        <span
          key={p.id}
          className="hub-particle"
          style={{
            left: `${p.left}%`,
            animationDelay: `-${p.delay}s`,
            animationDuration: `${p.duration}s`,
            opacity: p.opacity,
            transform: `scale(${p.scale})`,
          }}
        />
      ))}
    </div>
  );
}

// ── Top status bar — live signal / eval p50 / clock ───────────────
function StatusBar({ now }) {
  const time = now.toISOString().slice(11, 19) + " UTC";
  return (
    <div className="hub-status">
      <div className="hub-status-left">
        <span className="status-dot" aria-hidden="true" />
        <b>VORTEXBLACK</b>
        <span className="hub-status-sep" aria-hidden="true">·</span>
        <span>TEX AEGIS</span>
        <span className="hub-status-sep" aria-hidden="true">·</span>
        <span className="green">GATE LIVE</span>
      </div>
      <div className="hub-status-right">
        <span>EVAL <b>p50 178MS</b></span>
        <span className="hub-status-sep" aria-hidden="true">·</span>
        <span>RECEIPTS <b>SHA-256</b></span>
        <span className="hub-status-sep" aria-hidden="true">·</span>
        <span className="hub-clock">{time}</span>
      </div>
    </div>
  );
}

// ── Demo ticker — drifting verdicts (looks alive on first paint) ──────
const TICKER_LINES = [
  { v: "PERMIT",  s: "EMAIL:OUTBOUND",   t: "Quarterly performance summary attached.",       g: "✓" },
  { v: "ABSTAIN", s: "API:WEBHOOK",      t: "POST /v1/contacts — 384 PII fields detected.",   g: "?" },
  { v: "FORBID",  s: "EMAIL:OUTBOUND",   t: "Complaint forwarded with internal counsel reply.", g: "×" },
  { v: "PERMIT",  s: "SLACK:#general",   t: "Reminder — town hall moved to Thursday 2pm.",    g: "✓" },
  { v: "ABSTAIN", s: "API:OUTBOUND",     t: "Contains unverifiable financial projection.",     g: "?" },
  { v: "FORBID",  s: "EMAIL:DRAFT",      t: "Includes claim that does not match retrieval.",   g: "×" },
  { v: "PERMIT",  s: "DOC:EXPORT",       t: "Onboarding packet — public-cleared content.",     g: "✓" },
  { v: "ABSTAIN", s: "API:EXTERNAL",     t: "DELETE /users/* — irreversible bulk action.",     g: "?" },
];

function DemoTicker() {
  const [tick, setTick] = useState(0);
  useEffect(() => {
    const id = setInterval(() => setTick((t) => t + 1), 1800);
    return () => clearInterval(id);
  }, []);
  const offset = tick % TICKER_LINES.length;
  const visible = [];
  for (let i = 0; i < 3; i++) visible.push(TICKER_LINES[(offset + i) % TICKER_LINES.length]);
  return (
    <div className="demo-ticker" aria-label="Live verdict stream demonstration">
      <div className="demo-ticker-head">
        <span className="demo-ticker-pulse" aria-hidden="true" />
        <span>LIVE STREAM</span>
        <span className="demo-ticker-meta">verdicts • last 60s • sample</span>
      </div>
      {visible.map((row, i) => (
        <div className={`demo-ticker-row tier-${i}`} key={`${tick}-${i}`}>
          <span className={`demo-ticker-glyph v-${row.v.toLowerCase()}`}>{row.g}</span>
          <span className="demo-ticker-source">{row.s}</span>
          <span className="demo-ticker-body">{row.t}</span>
          <span className={`demo-ticker-verdict ${row.v.toLowerCase()}`}>{row.v}</span>
        </div>
      ))}
    </div>
  );
}

// ── Anatomy strip — three columns ──────────────────────────────────────
function AnatomyStrip() {
  const cards = [
    {
      n: "01",
      h: "WATCHES",
      b: "Email, Slack, API calls, deploys, DB queries — every outbound move an agent tries to make.",
    },
    {
      n: "02",
      h: "VERDICTS",
      b: "Permit, Abstain, Forbid — issued in 178ms with the exact policy line that triggered it.",
    },
    {
      n: "03",
      h: "RECEIPTS",
      b: "Hash-chained, HMAC-signed evidence of every decision. Audit-ready by default.",
    },
  ];
  return (
    <div className="anatomy-strip">
      {cards.map((c) => (
        <div className="anatomy-card" key={c.n}>
          <div className="num">{c.n}</div>
          <h3 className="h">{c.h}</h3>
          <div className="b">{c.b}</div>
        </div>
      ))}
    </div>
  );
}

// ── Leaderboard ────────────────────────────────────────────────────────
function Leaderboard({ rows, dateKey, ownHandle }) {
  if (!rows || rows.length === 0) return null;
  const top = rows.slice(0, 8);
  return (
    <div className="hub-leaderboard">
      <div className="leaderboard-head">
        <h3>ARCADE LEADERBOARD</h3>
        <div className="leaderboard-meta">
          <span>UTC {dateKey}</span>
          <span className="hub-status-sep" aria-hidden="true">·</span>
          <span>TOP 8 of {rows.length}</span>
        </div>
      </div>
      <div className="leaderboard-table">
        <div className="leaderboard-row leaderboard-th">
          <span>RANK</span>
          <span>OPERATOR</span>
          <span className="num-col">RATING</span>
          <span className="num-col">SCORE</span>
        </div>
        {top.map((r, i) => {
          const isOwn = ownHandle && r.handle === ownHandle;
          const score = r.score ?? r.total ?? 0;
          const rating = r.rating || "—";
          return (
            <div className={`leaderboard-row ${isOwn ? "own" : ""}`} key={`${r.handle}-${i}`}>
              <span className="rank">
                <span className={`rank-num rank-${i + 1}`}>{String(i + 1).padStart(2, "0")}</span>
              </span>
              <span className="handle">{r.handle}{isOwn && <em> · YOU</em>}</span>
              <span className="num-col">{rating}</span>
              <span className="num-col score">{score}</span>
            </div>
          );
        })}
      </div>
    </div>
  );
}

// ── Hub avatar ─────────────────────────────────────────────────────────
function HubAvatar({ now }) {
  const frameRef = useRef(null);
  const rafRef = useRef(0);
  const targetRef = useRef({ x: 0, y: 0 });
  const currentRef = useRef({ x: 0, y: 0 });

  useEffect(() => {
    if (typeof window === "undefined") return;

    function onMove(e) {
      // Use the whole hero area as the parallax field, not just the avatar,
      // so the head tracks the cursor naturally as you read the headline.
      const hero = document.querySelector(".hub-hero");
      if (!hero) return;
      const r = hero.getBoundingClientRect();
      const cx = r.left + r.width / 2;
      const cy = r.top + r.height / 2;
      // Normalize to [-1, 1] across the hero rect, clamped.
      const nx = Math.max(-1, Math.min(1, (e.clientX - cx) / (r.width / 2)));
      const ny = Math.max(-1, Math.min(1, (e.clientY - cy) / (r.height / 2)));
      targetRef.current = { x: nx, y: ny };
    }
    function onLeave() {
      targetRef.current = { x: 0, y: 0 };
    }

    function tick() {
      // Smooth easing toward target — no jitter, COD-portrait feel.
      const c = currentRef.current;
      const t = targetRef.current;
      c.x += (t.x - c.x) * 0.08;
      c.y += (t.y - c.y) * 0.08;
      const el = frameRef.current;
      if (el) {
        // Max ~6° rotation, plus a tiny translate for depth.
        const rotY = c.x * 6;
        const rotX = -c.y * 4;
        const tx = c.x * 6;
        const ty = c.y * 4;
        el.style.transform =
          `translate3d(${tx}px, ${ty}px, 0) rotateY(${rotY}deg) rotateX(${rotX}deg)`;
      }
      rafRef.current = requestAnimationFrame(tick);
    }

    window.addEventListener("mousemove", onMove);
    window.addEventListener("mouseleave", onLeave);
    rafRef.current = requestAnimationFrame(tick);
    return () => {
      window.removeEventListener("mousemove", onMove);
      window.removeEventListener("mouseleave", onLeave);
      cancelAnimationFrame(rafRef.current);
    };
  }, []);

  return (
    <div className="hub-avatar">
      <div className="avatar-glow" aria-hidden="true" />
      <div className="avatar-frame" ref={frameRef}>
        <img src="/tex/tex-full.png" alt="Tex — the gate" />
        <div className="eye-scan" aria-hidden="true" />
      </div>
    </div>
  );
}

// ── Component ─────────────────────────────────────────────────────────
export default function Hub({ onPlayArcade, onOpenWhatIsTex }) {
  const [now, setNow] = useState(() => new Date());
  const [board, setBoard] = useState({ entries: [] });
  const [handle, setHandle] = useState("");
  const dateKey = todayKey();

  useEffect(() => {
    const id = setInterval(() => setNow(new Date()), 1000);
    return () => clearInterval(id);
  }, []);

  useEffect(() => {
    setBoard(getDailyLeaderboard());
    setHandle(getHandle() || "");
  }, []);

  const handleArcade = () => { clickSfx(); onPlayArcade?.(); };
  const handleWhat = () => { clickSfx(); onOpenWhatIsTex?.(); };
  const handleAudit = () => { clickSfx(); /* link follows naturally */ };

  return (
    <div className="hub-stage">
      <div className="hub-grid-bg" aria-hidden="true" />
      <div className="hub-haze" aria-hidden="true" />
      <AmbientParticles count={32} />
      <div className="hub-scanlines" aria-hidden="true" />

      <StatusBar now={now} />

      <div className="hub-frame">
        <div className="hub-hero">
          <div className="hub-hero-text">
            <div className="hub-eyebrow">
              <span className="hub-eyebrow-mark" aria-hidden="true" />
              <span>FOR TEAMS RUNNING AI SDRS &amp; OUTBOUND AGENTS</span>
            </div>

            <h1 className="hub-headline">
              <span className="glow-line">THE GATE</span>
              <span className="glow-line">BETWEEN AI</span>
              <span className="glow-line">AND THE</span>
              <span className="glow-line">REAL WORLD.</span>
            </h1>

            <p className="hub-sub">
              Tex inspects every email, message, query, and deploy your AI
              agents try to send.
              <b> PERMIT, ABSTAIN, or FORBID</b> in 178ms — with a
              hash-chained, signed receipt for every decision.
            </p>

            <div className="hub-cta-row">
              <button
                className="btn-cta breathe"
                onClick={handleArcade}
                aria-label="Enter Tex Arcade — gate defense"
              >
                <span className="btn-cta-label">▶ ENTER ARCADE</span>
                <span className="btn-cta-meta">play the live gate · 60s</span>
              </button>
              <a
                className="btn-audit"
                href="mailto:matt@texaegis.com?subject=AI%20Outbound%20Audit%20%E2%80%94%2020%20Free%20Emails&body=Hi%20Matt%2C%20I%27d%20like%20a%20free%20Tex%20audit%20on%2020%20of%20our%20outbound%20AI%20emails.%20Our%20company%3A%20%5B%5D.%20Outbound%20stack%3A%20%5B%5D."
                onClick={handleAudit}
                aria-label="Request a free 20-email AI outbound audit"
              >
                <span className="btn-audit-label">FREE AI OUTBOUND AUDIT →</span>
                <span className="btn-audit-meta">we evaluate 20 of your real outbound emails</span>
              </a>
              <button
                className="btn-tertiary"
                onClick={handleWhat}
                aria-label="What is Tex"
              >
                WHAT IS TEX? →
              </button>
            </div>

            <div className="hub-hero-telemetry">
              <span>EVAL <b>p50 178MS</b></span>
              <span className="hub-status-sep" aria-hidden="true">·</span>
              <span>RECEIPTS <b>SHA-256 + HMAC</b></span>
              <span className="hub-status-sep" aria-hidden="true">·</span>
              <span>SURFACES <b>EMAIL · API · SLACK · DB · DEPLOY</b></span>
            </div>

            <DemoTicker />
          </div>

          <aside className="hub-hero-aside">
            <HubAvatar now={now} />
            <div className="hub-aside-caption">
              <div className="caption-quote">
                "I see what your agents are about to send.
                <br />I let the safe ones through. I stop the rest."
              </div>
              <div className="caption-attr">— TEX</div>
            </div>
          </aside>
        </div>

        <AnatomyStrip />

        <Leaderboard
          rows={board.entries || []}
          dateKey={dateKey}
          ownHandle={handle}
        />

        <div className="hub-rules-foot">
          <div className="rules-title">RULES OF THE GATE</div>
          <div className="rules-grid">
            <div><span className="rules-dot" style={{background:"#5FFA9F"}} /> GREEN — let it through</div>
            <div><span className="rules-dot" style={{background:"#FFD83D"}} /> ORANGE — stand under to capture</div>
            <div><span className="rules-dot" style={{background:"#FF4747"}} /> RED — shoot it down</div>
            <div><kbd>← →</kbd> move · <kbd>SPACE</kbd> fire · <kbd>ESC</kbd> bail</div>
          </div>
        </div>

        <footer className="hub-foot">
          <div>VORTEXBLACK · TEX AEGIS · {dateKey}</div>
          <div className="hub-foot-meta">
            <span>texaegis.com</span>
            <span className="hub-status-sep" aria-hidden="true">·</span>
            <span>built by Matt Nardizzi</span>
          </div>
        </footer>
      </div>
    </div>
  );
}
