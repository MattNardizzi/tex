import React, { useEffect, useMemo, useRef, useState } from "react";
import { clickSfx } from "../lib/sounds.js";
import {
  hasPlayedToday,
  todayResult,
  getDailyLeaderboard,
  getHandle,
} from "../lib/leaderboard.js";
import { msUntilNextShift, formatCountdown, todayKey } from "../lib/dailyShift.js";
import { SURFACES } from "../lib/messages.js";

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

// ── Top status bar — build label / ops / breach / clock ───────────────
function StatusBar({ now, breachCount }) {
  const time = now.toISOString().slice(11, 19) + " UTC";
  return (
    <div className="hub-status">
      <div className="hub-status-left">
        <span className="status-dot" aria-hidden="true" />
        <b>VORTEXBLACK</b>
        <span className="hub-status-sep" aria-hidden="true">·</span>
        <span>TEX AEGIS / ARENA</span>
        <span className="hub-status-sep" aria-hidden="true">·</span>
        <span>BUILD 0.14.2</span>
      </div>
      <div className="hub-status-right">
        <span>OPERATORS ONLINE <b>{1247 + (now.getSeconds() % 12)}</b></span>
        <span className="hub-status-sep" aria-hidden="true">·</span>
        <span>BREACH WATCH <b className="red">{breachCount}</b></span>
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
        <h3>SHIFT LEADERBOARD</h3>
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
          <span className="num-col">CAUGHT</span>
          <span className="num-col">SCORE</span>
        </div>
        {top.map((r, i) => {
          const isOwn = ownHandle && r.handle === ownHandle;
          return (
            <div className={`leaderboard-row ${isOwn ? "own" : ""}`} key={`${r.handle}-${i}`}>
              <span className="rank">
                <span className={`rank-num rank-${i + 1}`}>{String(i + 1).padStart(2, "0")}</span>
              </span>
              <span className="handle">{r.handle}{isOwn && <em> · YOU</em>}</span>
              <span className="num-col">{r.caught ?? "—"}</span>
              <span className="num-col score">{r.score}</span>
            </div>
          );
        })}
      </div>
    </div>
  );
}

// ── Hub avatar ─────────────────────────────────────────────────────────
function HubAvatar({ now }) {
  const lat = 174 + (now.getSeconds() % 9);
  const cps = (1240 + (now.getSeconds() * 13) % 380).toString();
  return (
    <div className="hub-avatar">
      <div className="avatar-glow" aria-hidden="true" />
      <div className="avatar-frame">
        <img src="/tex/tex-aegis.jpg" alt="Tex — the gate" />
        <div className="t-hex"><THexSvg title="" /></div>
        <div className="eye-scan" aria-hidden="true" />
        <div className="avatar-corner">
          <span className="dot" aria-hidden="true" />
          <span>TEX · ARMED</span>
        </div>
        <div className="avatar-tickers">
          <div>LAT <b>{lat}</b>MS</div>
          <div>CPS <b>{cps}</b></div>
          <div>POLICY <b>v3.2</b></div>
        </div>
        <div className="avatar-status">
          <div className="status-line">
            <span className="status-dot-mini" aria-hidden="true" />
            <span>GATE OPEN · INSPECTING</span>
          </div>
        </div>
        {/* corner brackets */}
        <span className="avatar-bracket tl" aria-hidden="true" />
        <span className="avatar-bracket tr" aria-hidden="true" />
        <span className="avatar-bracket bl" aria-hidden="true" />
        <span className="avatar-bracket br" aria-hidden="true" />
      </div>
    </div>
  );
}

// ── Mini countdown to next daily reset ────────────────────────────────
function NextShiftCountdown({ now }) {
  const ms = msUntilNextShift();
  return (
    <div className="next-shift">
      <span className="next-shift-label">NEXT SHIFT</span>
      <span className="next-shift-time">{formatCountdown(ms)}</span>
      <span className="next-shift-note">UTC reset</span>
    </div>
  );
}

// ── Component ─────────────────────────────────────────────────────────
export default function Hub({ onPlayDaily, onPlayTraining, onOpenWhatIsTex }) {
  const [now, setNow] = useState(() => new Date());
  const [played, setPlayed] = useState(false);
  const [todayRes, setTodayRes] = useState(null);
  const [board, setBoard] = useState({ rows: [] });
  const [handle, setHandle] = useState("");
  const dateKey = todayKey();

  useEffect(() => {
    const id = setInterval(() => setNow(new Date()), 1000);
    return () => clearInterval(id);
  }, []);

  useEffect(() => {
    setPlayed(hasPlayedToday());
    setTodayRes(todayResult());
    setBoard(getDailyLeaderboard());
    setHandle(getHandle() || "");
  }, []);

  const breachCount = useMemo(() => {
    // deterministic but date-stable, avoids flicker
    const d = new Date(dateKey + "T00:00:00Z");
    return 41 + ((d.getUTCDate() * 7 + d.getUTCMonth() * 13) % 19);
  }, [dateKey]);

  const handleDaily = () => {
    clickSfx();
    if (played) {
      onPlayTraining();
    } else {
      onPlayDaily();
    }
  };
  const handleTraining = () => { clickSfx(); onPlayTraining(); };
  const handleWhat = () => { clickSfx(); onOpenWhatIsTex(); };

  return (
    <div className="hub-stage">
      <div className="hub-grid-bg" aria-hidden="true" />
      <div className="hub-haze" aria-hidden="true" />
      <AmbientParticles count={32} />
      <div className="hub-scanlines" aria-hidden="true" />

      <StatusBar now={now} breachCount={breachCount} />

      <div className="hub-frame">
        <div className="hub-hero">
          <div className="hub-hero-text">
            <div className="hub-eyebrow">
              <span className="hub-eyebrow-mark" aria-hidden="true" />
              <span>VORTEXBLACK / TEX AEGIS · LIVE GATE</span>
            </div>

            <h1 className="hub-headline">
              <span className="glow-line">THE GATE</span>
              <span className="glow-line">BETWEEN AI</span>
              <span className="glow-line">AND THE</span>
              <span className="glow-line">REAL WORLD.</span>
            </h1>

            <p className="hub-sub">
              Every email, API call, message, and deploy your agents try to send —
              evaluated in <b>178ms</b> against policy, retrieval, and contradiction checks.
              <br />
              <span className="hub-sub-strong">
                Work a 90-second shift. See if you can keep up.
              </span>
            </p>

            <div className="hub-cta-row">
              <button
                className="btn-cta breathe"
                onClick={handleDaily}
                aria-label={played ? "Daily shift completed — start training" : "Start today's shift"}
              >
                <span className="btn-cta-label">
                  {played ? "▶ TRAIN AGAIN" : "▶ START TODAY'S SHIFT"}
                </span>
                <span className="btn-cta-meta">
                  {played
                    ? `Today: ${todayRes?.score ?? "—"} pts`
                    : "90s · 32 actions · one daily run"}
                </span>
              </button>
              <button
                className="btn-secondary"
                onClick={handleTraining}
                aria-label="Practice mode"
              >
                <span className="btn-secondary-label">PRACTICE</span>
                <span className="btn-secondary-meta">unlimited · no leaderboard</span>
              </button>
              <button
                className="btn-tertiary"
                onClick={handleWhat}
                aria-label="What is Tex"
              >
                WHAT IS TEX? →
              </button>
            </div>

            <NextShiftCountdown now={now} />

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

        <div className="telemetry-row">
          <span>EVAL <b>178</b>MS p50</span>
          <span>BLOCKS <b className="red">{(breachCount * 1.7).toFixed(0)}</b>/HR</span>
          <span>PERMIT RATE <b className="green">94.2%</b></span>
          <span>POLICY HASH <b>0xa4f1·c082</b></span>
          <span>RECEIPTS <b>SHA-256 + HMAC</b></span>
          <span>UPTIME <b className="green">99.99%</b></span>
        </div>

        <AnatomyStrip />

        <Leaderboard
          rows={board.rows || []}
          dateKey={dateKey}
          ownHandle={handle}
        />

        <div className="hub-rules-foot">
          <div className="rules-title">RULES OF THE SHIFT</div>
          <div className="rules-grid">
            <div><kbd>1</kbd> PERMIT — clean & on-policy</div>
            <div><kbd>2</kbd> ABSTAIN — escalate · needs human</div>
            <div><kbd>3</kbd> FORBID — block & log</div>
            <div><kbd>SPACE</kbd> hold to inspect · <kbd>ESC</kbd> bail</div>
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
