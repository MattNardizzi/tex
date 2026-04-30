import React, { useEffect, useMemo, useRef, useState } from 'react';

/* ────────────────────────────────────────────────────────────────────
 * The Sevenfold — texaegis.com homepage hero.
 *
 * One closed cryptographic chain. Seven layers running live, one at
 * each vertex. Tex's sigil at the center as the witness. A pulse of
 * light traverses the chain, completing the full circuit (Discovery →
 * Registration → ... → Learning → back to Discovery) every ~6.5
 * seconds. The loop visibly closes, repeatedly, forever.
 *
 * No new dependencies. Pure React + SVG + RAF. Honors prefers-reduced-
 * motion. Mobile-responsive via preserveAspectRatio.
 * ──────────────────────────────────────────────────────────────────── */

const VIEW_W = 1600;
const VIEW_H = 980;
const CX = VIEW_W / 2;
const CY = VIEW_H / 2 + 12;

const R_HEPT  = 290;
const R_SIGIL = 168;
const STATION_W = 252;
const STATION_H = 138;
const STATION_OFFSET = 90;

function vertex(i, r = R_HEPT) {
  const angle = (-Math.PI / 2) + (i * 2 * Math.PI) / 7;
  return { x: CX + r * Math.cos(angle), y: CY + r * Math.sin(angle), angle };
}

const STATIONS = [
  { key: 'discovery',    n: '01', name: 'DISCOVERY' },
  { key: 'registration', n: '02', name: 'REGISTRATION' },
  { key: 'capability',   n: '03', name: 'CAPABILITY' },
  { key: 'evaluation',   n: '04', name: 'EVALUATION' },
  { key: 'enforcement',  n: '05', name: 'ENFORCEMENT' },
  { key: 'evidence',     n: '06', name: 'EVIDENCE' },
  { key: 'learning',     n: '07', name: 'LEARNING' },
].map((s, i) => ({ ...s, ...vertex(i) }));

const HEPT_PATH = (() => {
  const pts = STATIONS.map(s => `${s.x.toFixed(1)},${s.y.toFixed(1)}`);
  return `M${pts[0]} L${pts.slice(1).join(' L')} Z`;
})();

const SEGMENTS = (() => {
  const segs = [];
  let total = 0;
  for (let i = 0; i < STATIONS.length; i++) {
    const a = STATIONS[i];
    const b = STATIONS[(i + 1) % STATIONS.length];
    const len = Math.hypot(b.x - a.x, b.y - a.y);
    segs.push({ from: i, to: (i + 1) % STATIONS.length, len, cum: total });
    total += len;
  }
  return { list: segs, total };
})();

function sampleLoop(t) {
  const target = ((t % 1) + 1) % 1 * SEGMENTS.total;
  for (const seg of SEGMENTS.list) {
    if (target >= seg.cum && target < seg.cum + seg.len) {
      const local = (target - seg.cum) / seg.len;
      const a = STATIONS[seg.from];
      const b = STATIONS[seg.to];
      return { x: a.x + (b.x - a.x) * local, y: a.y + (b.y - a.y) * local, seg: seg.from, local };
    }
  }
  const a = STATIONS[0];
  return { x: a.x, y: a.y, seg: 0, local: 0 };
}

function stationBox(s) {
  const dirX = (s.x - CX) / R_HEPT;
  const dirY = (s.y - CY) / R_HEPT;
  const cx2 = s.x + dirX * STATION_OFFSET;
  const cy2 = s.y + dirY * STATION_OFFSET;
  return { bx: cx2 - STATION_W / 2, by: cy2 - STATION_H / 2, cx: cx2, cy: cy2 };
}

function hashFragment(seed) {
  let h1 = 0x811c9dc5 ^ seed;
  let h2 = 0xdeadbeef ^ (seed * 7919);
  for (let i = 0; i < 4; i++) {
    h1 = Math.imul(h1 ^ (seed + i), 0x01000193) >>> 0;
    h2 = Math.imul(h2 ^ (h1 + i), 0x85ebca6b) >>> 0;
  }
  return (h1.toString(16).padStart(8, '0') + h2.toString(16).padStart(8, '0')).slice(0, 16);
}
function shortHash(seed) {
  const h = hashFragment(seed);
  return `${h.slice(0, 4)}..${h.slice(-4)}`;
}

const CYCLE_MS = 6500;

function useReducedMotion() {
  const [reduced, setReduced] = useState(false);
  useEffect(() => {
    if (typeof window === 'undefined') return;
    const mq = window.matchMedia('(prefers-reduced-motion: reduce)');
    setReduced(mq.matches);
    const handler = (e) => setReduced(e.matches);
    mq.addEventListener?.('change', handler);
    return () => mq.removeEventListener?.('change', handler);
  }, []);
  return reduced;
}

function useSevenfoldClock() {
  const [tick, setTick] = useState(0);
  const startRef = useRef(performance.now());
  const reducedMotion = useReducedMotion();
  useEffect(() => {
    if (reducedMotion) { setTick(0); return; }
    let raf = 0;
    const step = (now) => { setTick(now - startRef.current); raf = requestAnimationFrame(step); };
    raf = requestAnimationFrame(step);
    return () => cancelAnimationFrame(raf);
  }, [reducedMotion]);
  const t = (tick % CYCLE_MS) / CYCLE_MS;
  const cycle = Math.floor(tick / CYCLE_MS);
  const pulse = sampleLoop(t);
  return { t, cycle, pulse, tick, reducedMotion };
}

export default function Sevenfold({ verdict, phase, counters, chain, calibration }) {
  const { t, cycle, pulse, tick, reducedMotion } = useSevenfoldClock();
  const [hovered, setHovered] = useState(null);

  const activeStation = useMemo(() => {
    for (let i = 0; i < STATIONS.length; i++) {
      const v = STATIONS[i];
      const d = Math.hypot(pulse.x - v.x, pulse.y - v.y);
      if (d < R_HEPT * 0.18) return i;
    }
    return -1;
  }, [pulse.x, pulse.y]);

  const verdictKey = verdict || 'idle';

  return (
    <section className={`sevenfold sevenfold-verdict-${verdictKey}`} aria-label="Tex — the sevenfold adjudicator">
      <div className="sevenfold-glass" aria-hidden="true" />
      <div className="sevenfold-vignette" aria-hidden="true" />

      <div className="sevenfold-eyebrow">
        <span className="sevenfold-pip" aria-hidden="true" />
        TEX&nbsp;·&nbsp;THE&nbsp;SEVENFOLD&nbsp;ADJUDICATOR&nbsp;·&nbsp;LIVE
      </div>

      <div className="sevenfold-counters" role="status">
        <CounterCell label="permit"  value={counters?.permit  ?? 0} tone="permit" />
        <CounterCell label="abstain" value={counters?.abstain ?? 0} tone="abstain" />
        <CounterCell label="forbid"  value={counters?.forbid  ?? 0} tone="forbid" />
      </div>

      <div className="sevenfold-stage">
        <svg
          viewBox={`0 0 ${VIEW_W} ${VIEW_H}`}
          xmlns="http://www.w3.org/2000/svg"
          preserveAspectRatio="xMidYMid meet"
          className="sevenfold-svg"
          role="img"
          aria-label="Seven-layer cryptographic governance loop"
        >
          <defs>
            <radialGradient id="sf-pulse-glow" cx="50%" cy="50%" r="50%">
              <stop offset="0%"   stopColor="var(--cyan-soft)" stopOpacity="1"   />
              <stop offset="35%"  stopColor="var(--cyan)"      stopOpacity="0.6" />
              <stop offset="100%" stopColor="var(--cyan)"      stopOpacity="0"   />
            </radialGradient>
            <radialGradient id="sf-sigil-aura" cx="50%" cy="50%" r="50%">
              <stop offset="0%"   stopColor="var(--cyan)"   stopOpacity="0.32" />
              <stop offset="55%"  stopColor="var(--cyan)"   stopOpacity="0.06" />
              <stop offset="100%" stopColor="var(--cyan)"   stopOpacity="0"    />
            </radialGradient>
            <radialGradient id="sf-eye-permit"  cx="50%" cy="50%" r="50%">
              <stop offset="0%"   stopColor="var(--green)"  stopOpacity="1"   />
              <stop offset="60%"  stopColor="var(--green)"  stopOpacity="0.4" />
              <stop offset="100%" stopColor="var(--green)"  stopOpacity="0"   />
            </radialGradient>
            <radialGradient id="sf-eye-abstain" cx="50%" cy="50%" r="50%">
              <stop offset="0%"   stopColor="var(--amber)"  stopOpacity="1"   />
              <stop offset="60%"  stopColor="var(--amber)"  stopOpacity="0.4" />
              <stop offset="100%" stopColor="var(--amber)"  stopOpacity="0"   />
            </radialGradient>
            <radialGradient id="sf-eye-forbid"  cx="50%" cy="50%" r="50%">
              <stop offset="0%"   stopColor="var(--red)"    stopOpacity="1"   />
              <stop offset="60%"  stopColor="var(--red)"    stopOpacity="0.4" />
              <stop offset="100%" stopColor="var(--red)"    stopOpacity="0"   />
            </radialGradient>
            <radialGradient id="sf-eye-idle"    cx="50%" cy="50%" r="50%">
              <stop offset="0%"   stopColor="var(--cyan)"   stopOpacity="1"   />
              <stop offset="60%"  stopColor="var(--cyan)"   stopOpacity="0.4" />
              <stop offset="100%" stopColor="var(--cyan)"   stopOpacity="0"   />
            </radialGradient>
            <filter id="sf-soft-glow" x="-50%" y="-50%" width="200%" height="200%">
              <feGaussianBlur stdDeviation="6" result="b" />
              <feMerge><feMergeNode in="b" /><feMergeNode in="SourceGraphic" /></feMerge>
            </filter>
            {STATIONS.map((s) => {
              const { bx, by } = stationBox(s);
              return (
                <clipPath key={`clip-${s.key}`} id={`sf-clip-${s.key}`}>
                  <rect x={bx + 12} y={by + 32} width={STATION_W - 24} height={STATION_H - 44} />
                </clipPath>
              );
            })}
          </defs>

          <BackgroundGrid />

          <circle cx={CX} cy={CY} r={R_HEPT + 22} fill="none"
                  stroke="var(--ink-ghost)" strokeWidth="1" strokeDasharray="2 6" opacity="0.32" />

          {/* THE CHAIN */}
          <path d={HEPT_PATH} fill="none"
                stroke="var(--cyan)" strokeWidth="2.4" opacity="0.72"
                strokeLinejoin="round" />
          <path d={HEPT_PATH} fill="none"
                stroke="var(--cyan-soft)" strokeWidth="0.8" opacity="0.5"
                strokeLinejoin="round" />

          <ChainHexMarks tick={tick} />

          {STATIONS.map((s, i) => {
            const isActive = activeStation === i;
            return (
              <line key={`spoke-${s.key}`}
                x1={CX} y1={CY} x2={s.x} y2={s.y}
                stroke={isActive ? 'var(--cyan-soft)' : 'var(--ink-ghost)'}
                strokeWidth={isActive ? 1.6 : 0.7}
                opacity={isActive ? 0.95 : 0.5}
                strokeDasharray={isActive ? '0' : '1 6'}
                style={{ transition: 'all 240ms var(--ease-out)' }} />
            );
          })}

          <TexSigil verdict={verdictKey} phase={phase} tick={tick} />

          {STATIONS.map((s, i) => (
            <Station
              key={s.key}
              station={s}
              index={i}
              active={activeStation === i}
              hovered={hovered === i}
              onHover={() => setHovered(i)}
              onLeave={() => setHovered((h) => (h === i ? null : h))}
              tick={tick}
              cycle={cycle}
              chain={chain}
              calibration={calibration}
              counters={counters}
              verdict={verdictKey}
            />
          ))}

          {!reducedMotion && (
            <g pointerEvents="none">
              {[0.014, 0.030, 0.05].map((dt, i) => {
                const p = sampleLoop(t - dt);
                return (
                  <circle key={`trail-${i}`} cx={p.x} cy={p.y}
                          r={5 - i * 1.3}
                          fill="var(--cyan)"
                          opacity={0.7 - i * 0.2} />
                );
              })}
              <circle cx={pulse.x} cy={pulse.y} r="44"
                      fill="url(#sf-pulse-glow)" opacity="0.85" />
              <circle cx={pulse.x} cy={pulse.y} r="6.5"
                      fill="var(--cyan-soft)"
                      style={{ filter: 'drop-shadow(0 0 8px var(--cyan))' }} />
              <text x={pulse.x} y={pulse.y - 22}
                    textAnchor="middle" className="sf-pulse-hash">
                {shortHash(cycle * 7 + pulse.seg)}
              </text>
            </g>
          )}
        </svg>

        <LoopCloseBadge tick={tick} cycle={cycle} />
      </div>

      <div className="sevenfold-tagline">
        <p className="sevenfold-tagline-row">
          <em>Discovery.</em> <em>Registration.</em> <em>Capability.</em>{' '}
          <em>Evaluation.</em> <em>Enforcement.</em> <em>Evidence.</em>{' '}
          <em>Learning.</em>
        </p>
        <p className="sevenfold-tagline-claim">
          One being. One chain. <span className="seam">No seam.</span>
        </p>
      </div>

      <div className="sevenfold-cta-row">
        <a className="sf-cta sf-cta-primary" href="#evaluation">
          See a live verdict <span aria-hidden="true">↓</span>
        </a>
        <a className="sf-cta sf-cta-secondary" href="/asi">
          Read the architecture <span aria-hidden="true">→</span>
        </a>
      </div>
    </section>
  );
}

function CounterCell({ label, value, tone }) {
  return (
    <div className={`sf-counter sf-counter-${tone}`}>
      <span className="sf-counter-pip" />
      <span className="sf-counter-label">{label}</span>
      <span className="sf-counter-value">{value.toLocaleString()}</span>
    </div>
  );
}

function BackgroundGrid() {
  const lines = [];
  const step = 80;
  for (let x = 0; x <= VIEW_W; x += step) {
    lines.push(<line key={`vx-${x}`} x1={x} y1={0} x2={x} y2={VIEW_H}
                     stroke="var(--ink-ghost)" strokeWidth="0.5" opacity="0.28" />);
  }
  for (let y = 0; y <= VIEW_H; y += step) {
    lines.push(<line key={`vy-${y}`} x1={0} y1={y} x2={VIEW_W} y2={y}
                     stroke="var(--ink-ghost)" strokeWidth="0.5" opacity="0.28" />);
  }
  return <g aria-hidden="true">{lines}</g>;
}

function ChainHexMarks({ tick }) {
  const COUNT = 56;
  const offset = (tick / 18000) % 1;
  const marks = [];
  for (let i = 0; i < COUNT; i++) {
    const t = (i / COUNT + offset) % 1;
    const p = sampleLoop(t);
    const ch = '0123456789abcdef'[(i * 7 + Math.floor(tick / 600)) & 15];
    marks.push(
      <text key={`hex-${i}`} x={p.x} y={p.y + 3.5}
            className="sf-chain-glyph"
            textAnchor="middle">{ch}</text>
    );
  }
  return <g aria-hidden="true">{marks}</g>;
}

function TexSigil({ verdict, phase, tick }) {
  const eyeFill =
    verdict === 'permit'  ? 'url(#sf-eye-permit)'  :
    verdict === 'abstain' ? 'url(#sf-eye-abstain)' :
    verdict === 'forbid'  ? 'url(#sf-eye-forbid)'  :
                            'url(#sf-eye-idle)';

  const hex = (r) => {
    const pts = [];
    for (let i = 0; i < 6; i++) {
      const a = (-Math.PI / 2) + (i * Math.PI) / 3;
      pts.push(`${(CX + r * Math.cos(a)).toFixed(1)},${(CY + r * Math.sin(a)).toFixed(1)}`);
    }
    return pts.join(' ');
  };

  const breathe = 1 + Math.sin(tick / 1100) * 0.012;

  return (
    <g aria-hidden="true">
      <circle cx={CX} cy={CY} r={R_SIGIL * 1.45} fill="url(#sf-sigil-aura)" />

      <polygon points={hex(R_SIGIL)}
               fill="none"
               stroke="var(--cyan-deep)" strokeWidth="1"
               opacity="0.65" />

      <g style={{ transformOrigin: `${CX}px ${CY}px`, transform: `scale(${breathe})` }}>
        <polygon points={hex(R_SIGIL * 0.84)}
                 fill="rgba(7,8,15,0.85)"
                 stroke="var(--cyan)" strokeWidth="1.6" />
        <polygon points={hex(R_SIGIL * 0.62)}
                 fill="none"
                 stroke="var(--cyan-deep)" strokeWidth="0.6"
                 opacity="0.5" />
        <polygon points={hex(R_SIGIL * 0.40)}
                 fill="none"
                 stroke="var(--cyan-deep)" strokeWidth="0.5"
                 opacity="0.35" />

        <g>
          <line x1={CX - 28} y1={CY - 22} x2={CX + 28} y2={CY - 22}
                stroke="var(--cyan)" strokeWidth="2.2" strokeLinecap="round" />
          <line x1={CX} y1={CY - 22} x2={CX} y2={CY + 28}
                stroke="var(--cyan)" strokeWidth="2.2" strokeLinecap="round" />
        </g>

        <g className={`sf-sigil-eye sf-eye-${verdict} sf-phase-${phase || 'idle'}`} filter="url(#sf-soft-glow)">
          <ellipse cx={CX} cy={CY - 60} rx="38" ry="6.5" fill={eyeFill} />
          <ellipse cx={CX} cy={CY - 60} rx="18" ry="2.4" fill="var(--cyan-soft)" opacity="0.95" />
        </g>
      </g>

      <text x={CX} y={CY + R_SIGIL * 0.84 + 22} textAnchor="middle" className="sf-sigil-status">
        TEX · ON DUTY
      </text>
      <text x={CX} y={CY + R_SIGIL * 0.84 + 40} textAnchor="middle" className="sf-sigil-substatus">
        seven layers · one chain · no seam
      </text>
    </g>
  );
}

function Station({ station, index, active, hovered, onHover, onLeave, tick, cycle, chain, calibration, counters, verdict }) {
  const { bx, by } = stationBox(station);
  const Body = STATION_BODIES[station.key];

  return (
    <g
      className={`sf-station sf-station-${station.key} ${active ? 'is-active' : ''} ${hovered ? 'is-hovered' : ''}`}
      onMouseEnter={onHover}
      onMouseLeave={onLeave}
      onFocus={onHover}
      onBlur={onLeave}
      tabIndex="0"
      role="button"
      aria-label={`Layer ${station.n} ${station.name}`}
    >
      <circle cx={station.x} cy={station.y} r="3.5"
              fill="var(--bg)" stroke="var(--cyan)" strokeWidth="1.4" />
      {active && (
        <>
          <circle cx={station.x} cy={station.y} r="9"
                  fill="none" stroke="var(--cyan-soft)" strokeWidth="1.4" opacity="0.9">
            <animate attributeName="r" from="6" to="20" dur="0.9s" repeatCount="1" />
            <animate attributeName="opacity" from="0.9" to="0" dur="0.9s" repeatCount="1" />
          </circle>
          <circle cx={station.x} cy={station.y} r="6"
                  fill="var(--cyan-soft)" />
        </>
      )}

      <line x1={station.x} y1={station.y}
            x2={bx + STATION_W / 2 - ((station.x - CX) / R_HEPT) * (STATION_W / 2)}
            y2={by + STATION_H / 2 - ((station.y - CY) / R_HEPT) * (STATION_H / 2)}
            stroke="var(--cyan-deep)"
            strokeWidth={active ? 1.4 : 0.9}
            opacity={active ? 0.95 : 0.55}
            style={{ transition: 'all 220ms var(--ease-out)' }} />

      <rect x={bx} y={by} width={STATION_W} height={STATION_H} rx="2" ry="2"
            fill="rgba(6,7,14,0.86)"
            stroke={active ? 'var(--cyan)' : 'var(--ink-ghost)'}
            strokeWidth={active ? 1.6 : 0.9}
            style={{ transition: 'stroke 240ms var(--ease-out), stroke-width 240ms var(--ease-out)' }} />

      <text x={bx + 12} y={by + 18} className="sf-station-eyebrow">
        {station.n} <tspan className="sf-station-eyebrow-name" dx="6">{station.name}</tspan>
      </text>
      <line x1={bx + 12} y1={by + 26} x2={bx + STATION_W - 12} y2={by + 26}
            stroke={active ? 'var(--cyan)' : 'var(--ink-ghost)'}
            strokeWidth="0.8" opacity={active ? 0.9 : 0.45}
            style={{ transition: 'all 240ms var(--ease-out)' }} />

      <g transform={`translate(${bx + 12}, ${by + 32})`}
         clipPath={`url(#sf-clip-${station.key})`}>
        <Body w={STATION_W - 24} h={STATION_H - 44}
              tick={tick} cycle={cycle}
              chain={chain} calibration={calibration}
              counters={counters} verdict={verdict} />
      </g>

      {active && (
        <g>
          <rect x={bx} y={by} width="10" height="2" fill="var(--cyan)" />
          <rect x={bx} y={by} width="2" height="10" fill="var(--cyan)" />
          <rect x={bx + STATION_W - 10} y={by + STATION_H - 2} width="10" height="2" fill="var(--cyan)" />
          <rect x={bx + STATION_W - 2}  y={by + STATION_H - 10} width="2" height="10" fill="var(--cyan)" />
        </g>
      )}
    </g>
  );
}

const STATION_BODIES = {
  discovery: ({ w, h, tick }) => {
    const ROWS = 4;
    const cycle = Math.floor(tick / 800);
    const agents = [
      'copilot-studio-fa3', 'bedrock-a91x', 'mcp:cursor-12',
      'agentforce-03', 'oai-asst-71', 'graph-sharepoint',
      'github-app-rl3', 'einstein-bot-44', 'amelia-cs-bot',
    ];
    const rows = [];
    for (let i = 0; i < ROWS; i++) {
      const a = agents[(cycle + i) % agents.length];
      const isNew = i === ROWS - 1;
      rows.push(
        <g key={i} transform={`translate(0, ${i * 18})`}>
          <circle cx="3" cy="6" r="2" fill={isNew ? 'var(--cyan-soft)' : 'var(--ink-faint)'} opacity={isNew ? 1 : 0.6} />
          <text x="12" y="9" className={`sf-row ${isNew ? 'sf-row-new' : ''}`}>{a}</text>
          {isNew && <text x={w - 4} y="9" textAnchor="end" className="sf-row-tag">NEW</text>}
        </g>
      );
    }
    return <g>{rows}<text x="0" y={h - 4} className="sf-station-foot">7 connectors · live</text></g>;
  },

  registration: ({ w, h, tick }) => {
    const cycle = Math.floor(tick / 1100);
    const states = [
      { id: 'agent-04',   tier: 'STANDARD',   life: 'ACTIVE'  },
      { id: 'support-12', tier: 'TRUSTED',    life: 'ACTIVE'  },
      { id: 'fa3-studio', tier: 'UNVERIFIED', life: 'PENDING' },
      { id: 'oai-71',     tier: 'STANDARD',   life: 'ACTIVE'  },
    ];
    const flashIdx = cycle % states.length;
    return (
      <g>
        {states.map((s, i) => {
          const lifeClr = s.life === 'PENDING' ? 'var(--amber)' :
                          s.life === 'QUARANTINED' ? 'var(--red)' : 'var(--green)';
          return (
            <g key={i} transform={`translate(0, ${i * 18})`} opacity={i === flashIdx ? 1 : 0.78}>
              <text x="0" y="9" className="sf-row">{s.id}</text>
              <text x={w - 60} y="9" textAnchor="end" className="sf-row-dim">{s.tier}</text>
              <rect x={w - 50} y="2" width="50" height="11" rx="1"
                    fill="rgba(0,0,0,0.4)" stroke={lifeClr} strokeWidth="0.6" />
              <text x={w - 25} y="10" textAnchor="middle" className="sf-row-life" fill={lifeClr}>{s.life}</text>
            </g>
          );
        })}
        <text x="0" y={h - 4} className="sf-station-foot">2,535 active · 312 held</text>
      </g>
    );
  },

  capability: ({ w, h, tick }) => {
    const cx = w / 2;
    const cy = (h - 16) / 2;
    const rOuter = Math.min(cx, cy) - 4;
    const breath = (Math.sin(tick / 700) * 0.08) + 0.92;
    const rays = 12;
    const lines = [];
    for (let i = 0; i < rays; i++) {
      const a = (i / rays) * Math.PI * 2;
      const allowed = [0, 1, 2, 3, 5, 6, 8, 9].includes(i);
      const len = (allowed ? rOuter * (0.7 + (i % 3) * 0.1) : rOuter * 0.35) * breath;
      lines.push(
        <line key={i}
              x1={cx} y1={cy}
              x2={cx + Math.cos(a) * len}
              y2={cy + Math.sin(a) * len}
              stroke={allowed ? 'var(--cyan)' : 'var(--red)'}
              strokeWidth="1"
              opacity={allowed ? 0.85 : 0.6} />
      );
    }
    return (
      <g>
        <circle cx={cx} cy={cy} r={rOuter}        fill="none" stroke="var(--ink-ghost)" strokeWidth="0.5" />
        <circle cx={cx} cy={cy} r={rOuter * 0.6}  fill="none" stroke="var(--ink-ghost)" strokeWidth="0.5" />
        {lines}
        <circle cx={cx} cy={cy} r="2.5" fill="var(--cyan-soft)" />
        <text x="0" y={h - 4} className="sf-station-foot">surface bound · 23 cells</text>
      </g>
    );
  },

  evaluation: ({ w, h, tick, verdict }) => {
    const cx = w - 22;
    const cy = (h - 16) / 2;
    const streams = [
      { y: 4,  label: 'IDENT' },
      { y: 16, label: 'CAPAB' },
      { y: 28, label: 'BEHAV' },
      { y: 40, label: 'DETER' },
      { y: 52, label: 'RETRV' },
      { y: 64, label: 'SPCST' },
      { y: 76, label: 'SEMNT' },
    ];
    const flashIdx = Math.floor(tick / 220) % 7;
    const verdictColor = verdict === 'forbid'  ? 'var(--red)' :
                         verdict === 'abstain' ? 'var(--amber)' :
                         verdict === 'permit'  ? 'var(--green)' : 'var(--cyan)';
    return (
      <g>
        {streams.map((s, i) => (
          <g key={i}>
            <text x="0" y={s.y + 3} className="sf-row-dim">{s.label}</text>
            <line x1="34" y1={s.y} x2={cx - 9} y2={cy}
                  stroke={i === flashIdx ? 'var(--cyan-soft)' : 'var(--cyan-deep)'}
                  strokeWidth={i === flashIdx ? 1.3 : 0.6}
                  opacity={i === flashIdx ? 1 : 0.55} />
          </g>
        ))}
        <circle cx={cx} cy={cy} r="9" fill="rgba(0,0,0,0.5)" stroke={verdictColor} strokeWidth="1.4" />
        <circle cx={cx} cy={cy} r="3.5" fill={verdictColor} />
        <text x="0" y={h - 4} className="sf-station-foot">7 streams · fused · 2.4ms</text>
      </g>
    );
  },

  enforcement: ({ w, h, tick }) => {
    const examples = [
      { line: 'wire $12,400 → vendor-91',          v: 'forbid'  },
      { line: 'email lead@acme.io',                 v: 'permit'  },
      { line: 'sharepoint.share → public-link',     v: 'forbid'  },
      { line: 'refund r_42 · $48',                  v: 'permit'  },
      { line: 'dm @external.client',                v: 'abstain' },
      { line: 'merge PR#4421 → main',               v: 'permit'  },
    ];
    const cycle = Math.floor(tick / 1500);
    const e = examples[cycle % examples.length];
    const vColor = e.v === 'forbid'  ? 'var(--red)'   :
                   e.v === 'abstain' ? 'var(--amber)' : 'var(--green)';
    return (
      <g>
        <text x="0" y="11" className="sf-row-dim">action_in</text>
        <text x="0" y="28" className="sf-row" style={{ fontSize: 11 }}>{e.line}</text>
        <rect x="0" y="40" width={w} height="22" fill="rgba(0,0,0,0.45)"
              stroke="var(--ink-ghost)" strokeWidth="0.6" />
        <line x1={w * 0.6} y1="40" x2={w * 0.6} y2="62" stroke={vColor} strokeWidth="1.5" />
        <circle cx={w * 0.28} cy="51" r="4" fill={vColor} />
        <text x={w * 0.78} y="54" textAnchor="middle" className="sf-row" fill={vColor} style={{ fontWeight: 600, letterSpacing: '0.18em' }}>
          {e.v.toUpperCase()}
        </text>
        <text x="0" y={h - 4} className="sf-station-foot">gate · fail-closed · 1.4ms</text>
      </g>
    );
  },

  evidence: ({ w, h, tick }) => {
    const ROWS = 5;
    const c = Math.floor(tick / 700);
    const offset = (tick / 700) % 1;
    const rows = [];
    for (let i = 0; i < ROWS; i++) {
      const seed = c - i;
      const hash = hashFragment(seed);
      const y = i * 17 + offset * 17;
      const op = 1 - (i / ROWS) * 0.7;
      rows.push(
        <g key={i} transform={`translate(0, ${y})`} opacity={op}>
          <text x="0" y="9" className="sf-row-mono" style={{ fontSize: 10.5 }}>
            {hash.slice(0, 8)}..{hash.slice(-4)}
          </text>
          {i < ROWS - 1 && (
            <text x={w - 2} y="9" textAnchor="end" className="sf-row-dim" style={{ fontSize: 9 }}>←</text>
          )}
        </g>
      );
    }
    return (
      <g>
        {rows}
        <text x="0" y={h - 4} className="sf-station-foot">chain · sealed · 0 gaps</text>
      </g>
    );
  },

  learning: ({ w, h, tick }) => {
    const POINTS = 22;
    const data = [];
    for (let i = 0; i < POINTS; i++) {
      const x = (i / (POINTS - 1)) * w;
      const phase = (tick / 800) - i * 0.3;
      const y = (h - 22) / 2 + Math.sin(phase) * 6 + Math.sin(phase * 0.5) * 4;
      data.push(`${i === 0 ? 'M' : 'L'}${x.toFixed(1)},${y.toFixed(1)}`);
    }
    const recal = (tick % 4500) < 600;
    return (
      <g>
        <line x1="0" y1={(h - 22) / 2} x2={w} y2={(h - 22) / 2}
              stroke="var(--ink-ghost)" strokeWidth="0.5" strokeDasharray="2 4" />
        <path d={data.join(' ')} fill="none" stroke="var(--cyan)" strokeWidth="1.2" opacity="0.9" />
        {recal && (
          <text x={w} y="11" textAnchor="end" className="sf-row-tag" fill="var(--amber)">↻ recalibrated</text>
        )}
        <text x="0" y={h - 4} className="sf-station-foot">drift · ▲0.005 permit_t</text>
      </g>
    );
  },
};

function LoopCloseBadge({ tick, cycle }) {
  const phaseInCycle = (tick % CYCLE_MS) / CYCLE_MS;
  const visible = phaseInCycle < 0.14;
  const opacity = visible ? Math.max(0, 1 - (phaseInCycle / 0.14)) : 0;
  return (
    <div className="sevenfold-loop-badge" style={{ opacity }}>
      <span className="lcb-bar" />
      <span className="lcb-text">
        LOOP CLOSED · cycle {String(cycle).padStart(4, '0')} · chain sealed{' '}
        <span className="lcb-hash">{shortHash(cycle * 31)}</span>
      </span>
      <span className="lcb-bar" />
    </div>
  );
}
