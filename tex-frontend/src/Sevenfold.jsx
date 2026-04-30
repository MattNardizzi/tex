import React, { useEffect, useMemo, useRef, useState } from 'react';
import texHero from './tex-hero.png';

/* ────────────────────────────────────────────────────────────────────
 * The Sevenfold — texaegis.com homepage hero (v3).
 *
 * Composition:
 *   Tex stands center, life-sized. Around him orbits a single closed
 *   cryptographic ring — viewed at a slight perspective tilt so it
 *   reads as a halo of governance encircling the being. Seven layer
 *   nodes sit on the ring at evenly distributed positions. A pulse of
 *   light traverses the ring, lighting each node as it passes. The
 *   loop closes, repeatedly, forever.
 *
 *   Tex is the system. The system is him.
 *
 * Pure React + SVG + RAF. No new dependencies. Honors prefers-reduced-
 * motion. Mobile-responsive. Atmospheric layers (fog, grid, scanlines,
 * bloom) all SVG/CSS — no canvas, no WebGL.
 * ──────────────────────────────────────────────────────────────────── */

/* ─── Geometry ─────────────────────────────────────────────────────── */

const VIEW_W = 1600;
const VIEW_H = 1100;
const CX = VIEW_W / 2;
const CY = 600; // ring center — at chest height of avatar

// The ring is drawn as a perspective ellipse. Major axis horizontal,
// minor axis vertical (foreshortened to suggest tilt).
const RING_RX = 600;
const RING_RY = 140;

// Tex avatar dimensions on stage.
const TEX_W = 580;
const TEX_H = 720;
const TEX_X = CX - TEX_W / 2;
const TEX_Y = CY - 360; // place chest emblem near ring center

// Card dimensions for each layer node.
const CARD_W = 232;
const CARD_H = 96;

// Compute node position on the perspective ring at angle theta.
// theta=0 is right side (3 o'clock), increases counterclockwise.
function ringPoint(theta) {
  return {
    x: CX + RING_RX * Math.cos(theta),
    y: CY + RING_RY * Math.sin(theta),
  };
}

// Seven layer nodes spaced evenly on the ring, starting from top
// (Discovery), proceeding clockwise. Card positions are hand-tuned so
// every card stays inside the viewport and never overlaps the avatar
// or another card.
const STATIONS_RAW = [
  // theta in radians, measured from +x axis going clockwise (so -π/2 = top)
  // cardX/cardY: explicit center position of the card in viewBox coords
  { key: 'discovery',    n: '01', name: 'DISCOVERY',    theta: -Math.PI / 2,                                cardX: CX,           cardY: 70  },
  { key: 'registration', n: '02', name: 'REGISTRATION', theta: -Math.PI / 2 + (2 * Math.PI) / 7,           cardX: VIEW_W - 180, cardY: 270 },
  { key: 'capability',   n: '03', name: 'CAPABILITY',   theta: -Math.PI / 2 + (4 * Math.PI) / 7,           cardX: VIEW_W - 180, cardY: 580 },
  { key: 'evaluation',   n: '04', name: 'EVALUATION',   theta: -Math.PI / 2 + (6 * Math.PI) / 7,           cardX: VIEW_W - 220, cardY: 880 },
  { key: 'enforcement',  n: '05', name: 'ENFORCEMENT',  theta: -Math.PI / 2 + (8 * Math.PI) / 7,           cardX: 220,          cardY: 880 },
  { key: 'evidence',     n: '06', name: 'EVIDENCE',     theta: -Math.PI / 2 + (10 * Math.PI) / 7,          cardX: 180,          cardY: 580 },
  { key: 'learning',     n: '07', name: 'LEARNING',     theta: -Math.PI / 2 + (12 * Math.PI) / 7,          cardX: 180,          cardY: 270 },
];

const STATIONS = STATIONS_RAW.map((s) => {
  const p = ringPoint(s.theta);
  // Front-half: lower portion of ring (sin > -0.15). Drawn after avatar.
  const isFront = Math.sin(s.theta) > -0.15;
  return { ...s, x: p.x, y: p.y, isFront };
});

function cardPosition(s) {
  return {
    cx: s.cardX,
    cy: s.cardY,
    bx: s.cardX - CARD_W / 2,
    by: s.cardY - CARD_H / 2,
  };
}

/* ─── Hash helpers ────────────────────────────────────────────────── */

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

/* ─── Clock ────────────────────────────────────────────────────────── */

const CYCLE_MS = 7000;

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
    const step = (now) => {
      setTick(now - startRef.current);
      raf = requestAnimationFrame(step);
    };
    raf = requestAnimationFrame(step);
    return () => cancelAnimationFrame(raf);
  }, [reducedMotion]);

  // t ∈ [0, 1) — phase along the ring perimeter
  const t = (tick % CYCLE_MS) / CYCLE_MS;
  const cycle = Math.floor(tick / CYCLE_MS);

  // Pulse position on the ring. Same starting orientation as STATIONS.
  const pulseTheta = -Math.PI / 2 + t * 2 * Math.PI;
  const pulseP = ringPoint(pulseTheta);
  const pulseFront = Math.sin(pulseTheta) > -0.15;

  return { t, cycle, tick, reducedMotion, pulseP, pulseTheta, pulseFront };
}

/* ─── Component ───────────────────────────────────────────────────── */

export default function Sevenfold({ verdict, phase, counters }) {
  const { t, cycle, tick, reducedMotion, pulseP, pulseTheta, pulseFront } = useSevenfoldClock();
  const [hovered, setHovered] = useState(null);

  // Active station — pulse is currently within ~12° of which node.
  const activeStation = useMemo(() => {
    let best = -1, bestD = Infinity;
    for (let i = 0; i < STATIONS.length; i++) {
      const s = STATIONS[i];
      // angular distance, wrapped
      let d = Math.abs(((pulseTheta - s.theta + Math.PI) % (2 * Math.PI)) - Math.PI);
      if (d < bestD) { bestD = d; best = i; }
    }
    return bestD < 0.32 ? best : -1;
  }, [pulseTheta]);

  const verdictKey = verdict || 'idle';

  // Split stations: back-half (drawn behind avatar) vs front-half (in front).
  const backStations = STATIONS.map((s, i) => ({ s, i })).filter(x => !x.s.isFront);
  const frontStations = STATIONS.map((s, i) => ({ s, i })).filter(x => x.s.isFront);

  return (
    <section className={`sevenfold sevenfold-verdict-${verdictKey}`} aria-label="Tex — the sevenfold adjudicator">
      {/* Atmospheric backdrop */}
      <div className="sf-bg" aria-hidden="true">
        <div className="sf-bg-grid" />
        <div className="sf-bg-glow" />
        <div className="sf-bg-fog" />
        <div className="sf-bg-scanlines" />
      </div>

      {/* Eyebrow */}
      <div className="sf-eyebrow">
        <span className="sf-eyebrow-pip" aria-hidden="true" />
        <span className="sf-eyebrow-text">TEX&nbsp;·&nbsp;THE&nbsp;SEVENFOLD&nbsp;ADJUDICATOR</span>
        <span className="sf-eyebrow-divider" />
        <span className="sf-eyebrow-live">LIVE</span>
      </div>

      {/* Counters */}
      <div className="sf-counters" role="status">
        <CounterCell label="permit"  value={counters?.permit  ?? 0} tone="permit"  />
        <CounterCell label="abstain" value={counters?.abstain ?? 0} tone="abstain" />
        <CounterCell label="forbid"  value={counters?.forbid  ?? 0} tone="forbid"  />
      </div>

      {/* The stage */}
      <div className="sf-stage">
        <svg
          viewBox={`0 0 ${VIEW_W} ${VIEW_H}`}
          xmlns="http://www.w3.org/2000/svg"
          preserveAspectRatio="xMidYMid meet"
          className="sf-svg"
          role="img"
          aria-label="Seven-layer cryptographic governance loop"
        >
          <defs>
            <radialGradient id="sf-pulse" cx="50%" cy="50%" r="50%">
              <stop offset="0%"   stopColor="#cef5ff" stopOpacity="1"   />
              <stop offset="35%"  stopColor="#5ee0ff" stopOpacity="0.7" />
              <stop offset="100%" stopColor="#5ee0ff" stopOpacity="0"   />
            </radialGradient>
            <radialGradient id="sf-aura" cx="50%" cy="50%" r="50%">
              <stop offset="0%"   stopColor="#5ee0ff" stopOpacity="0.30" />
              <stop offset="55%"  stopColor="#2fb8e0" stopOpacity="0.06" />
              <stop offset="100%" stopColor="#5ee0ff" stopOpacity="0"    />
            </radialGradient>
            <radialGradient id="sf-floor" cx="50%" cy="50%" r="50%">
              <stop offset="0%"   stopColor="#5ee0ff" stopOpacity="0.22" />
              <stop offset="60%"  stopColor="#5ee0ff" stopOpacity="0.04" />
              <stop offset="100%" stopColor="#5ee0ff" stopOpacity="0"    />
            </radialGradient>
            <linearGradient id="sf-ring-stroke" x1="0%" y1="0%" x2="100%" y2="0%">
              <stop offset="0%"   stopColor="#2fb8e0" stopOpacity="0.4" />
              <stop offset="50%"  stopColor="#9af0ff" stopOpacity="1"   />
              <stop offset="100%" stopColor="#2fb8e0" stopOpacity="0.4" />
            </linearGradient>
            <linearGradient id="sf-card-fill" x1="0%" y1="0%" x2="0%" y2="100%">
              <stop offset="0%"   stopColor="#0a0e1a" stopOpacity="0.92" />
              <stop offset="100%" stopColor="#04060c" stopOpacity="0.92" />
            </linearGradient>
            <filter id="sf-glow" x="-100%" y="-100%" width="300%" height="300%">
              <feGaussianBlur stdDeviation="8" />
            </filter>
            <filter id="sf-glow-sm" x="-100%" y="-100%" width="300%" height="300%">
              <feGaussianBlur stdDeviation="3" />
            </filter>
          </defs>

          {/* FLOOR DISC — a soft glowing ellipse at Tex's feet */}
          <ellipse cx={CX} cy={CY + 380} rx={420} ry={60}
                   fill="url(#sf-floor)" opacity="0.85" />

          {/* RING — back half (behind avatar) */}
          <RingArcBack tick={tick} reducedMotion={reducedMotion} />

          {/* Back-half station nodes (behind avatar) */}
          {backStations.map(({ s, i }) => (
            <StationNode
              key={s.key}
              station={s}
              index={i}
              active={activeStation === i}
              hovered={hovered === i}
              onHover={() => setHovered(i)}
              onLeave={() => setHovered(h => h === i ? null : h)}
              tick={tick}
              cycle={cycle}
              counters={counters}
              verdict={verdictKey}
            />
          ))}

          {/* Pulse on back half of ring */}
          {!reducedMotion && !pulseFront && <Pulse p={pulseP} cycle={cycle} t={t} />}

          {/* TEX — the avatar */}
          <g>
            {/* Soft aura behind avatar */}
            <ellipse cx={CX} cy={CY - 60} rx={340} ry={420}
                     fill="url(#sf-aura)" opacity="0.7" />
            <image
              href={texHero}
              x={TEX_X}
              y={TEX_Y}
              width={TEX_W}
              height={TEX_H}
              preserveAspectRatio="xMidYMid meet"
              style={{ filter: 'drop-shadow(0 0 30px rgba(94,224,255,0.18))' }}
            />
            {/* Eye-flash overlay synced to verdict */}
            <EyeFlash verdict={verdictKey} phase={phase} />
          </g>

          {/* RING — front half (in front of avatar's lower body) */}
          <RingArcFront tick={tick} reducedMotion={reducedMotion} />

          {/* Front-half station nodes */}
          {frontStations.map(({ s, i }) => (
            <StationNode
              key={s.key}
              station={s}
              index={i}
              active={activeStation === i}
              hovered={hovered === i}
              onHover={() => setHovered(i)}
              onLeave={() => setHovered(h => h === i ? null : h)}
              tick={tick}
              cycle={cycle}
              counters={counters}
              verdict={verdictKey}
            />
          ))}

          {/* Pulse on front half */}
          {!reducedMotion && pulseFront && <Pulse p={pulseP} cycle={cycle} t={t} />}

          {/* Connector from each card to its ring node */}
          {STATIONS.map((s, i) => {
            const cp = cardPosition(s);
            return (
              <g key={`con-${s.key}`}>
                <line x1={s.x} y1={s.y} x2={cp.cx} y2={cp.cy}
                      stroke={activeStation === i ? '#9af0ff' : '#2fb8e0'}
                      strokeWidth={activeStation === i ? 1.4 : 0.7}
                      opacity={activeStation === i ? 0.9 : 0.45}
                      strokeDasharray={activeStation === i ? '0' : '1 5'}
                      style={{ transition: 'all 240ms cubic-bezier(0.16,1,0.3,1)' }} />
              </g>
            );
          })}
        </svg>

        {/* Loop close badge */}
        <LoopCloseBadge tick={tick} cycle={cycle} />
      </div>

      {/* Tagline */}
      <div className="sf-tagline">
        <p className="sf-tagline-row">
          <em>Discovery.</em> <em>Registration.</em> <em>Capability.</em>{' '}
          <em>Evaluation.</em> <em>Enforcement.</em> <em>Evidence.</em>{' '}
          <em>Learning.</em>
        </p>
        <p className="sf-tagline-claim">
          One being. One chain. <span className="seam">No seam.</span>
        </p>
      </div>

      {/* CTAs */}
      <div className="sf-cta-row">
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

/* ─── Sub-components ──────────────────────────────────────────────── */

function CounterCell({ label, value, tone }) {
  return (
    <div className={`sf-counter sf-counter-${tone}`}>
      <span className="sf-counter-pip" />
      <span className="sf-counter-label">{label}</span>
      <span className="sf-counter-value">{value.toLocaleString()}</span>
    </div>
  );
}

/* Ring is drawn in two halves so the avatar can be sandwiched between
   them — back half draws first (behind), front half draws after (in
   front of avatar's lower body). Each half is a path along the
   appropriate arc of the ellipse. */

function ringPathArc(startTheta, endTheta) {
  // SVG ellipse arc from startTheta to endTheta on our ring.
  // We need to be careful: large-arc-flag depends on angular sweep.
  const start = ringPoint(startTheta);
  const end = ringPoint(endTheta);
  const sweep = ((endTheta - startTheta) + 2 * Math.PI) % (2 * Math.PI);
  const largeArc = sweep > Math.PI ? 1 : 0;
  // sweep-flag: 1 = clockwise. Our angles go clockwise (positive).
  return `M${start.x.toFixed(1)},${start.y.toFixed(1)} A${RING_RX},${RING_RY} 0 ${largeArc} 1 ${end.x.toFixed(1)},${end.y.toFixed(1)}`;
}

function RingArcBack({ tick }) {
  // Back half: theta from π to 2π (i.e. top of ring across to bottom-back-left → top → bottom-back-right)
  // Easier: in our ring, "back" is where sin(theta) < -0.15 (upper portion of ellipse).
  // That corresponds to theta ∈ (π + asin(0.15), 2π - asin(0.15)) ish.
  // Simpler: just split at theta = -0.15 and theta = π+0.15 with sin check.
  // Let's draw two arcs: one for the back upper-right portion, one for back upper-left.
  // Back portion is where y < CY - RING_RY*0.15  →  sin(theta) < -0.15
  // sin(theta) = -0.15 at theta = π + asin(0.15) ≈ π + 0.1506 and at theta = 2π - 0.1506
  // So back arc runs from theta = π + 0.1506 to theta = 2π - 0.1506 (the upper portion).
  const a = Math.PI + 0.1506;
  const b = 2 * Math.PI - 0.1506;
  const path = ringPathArc(a, b);

  const offset = (tick / 12000) * 200;

  return (
    <g>
      {/* Glow underlay */}
      <path d={path} fill="none" stroke="#5ee0ff" strokeWidth="6"
            opacity="0.18" filter="url(#sf-glow)" />
      {/* Main stroke */}
      <path d={path} fill="none" stroke="url(#sf-ring-stroke)" strokeWidth="1.6"
            opacity="0.7" strokeDasharray="3 4" strokeDashoffset={-offset} />
      {/* Hairline highlight */}
      <path d={path} fill="none" stroke="#cef5ff" strokeWidth="0.5" opacity="0.5" />
    </g>
  );
}

function RingArcFront({ tick }) {
  // Front portion: from b → 2π (= 0) → a, i.e. the lower portion of the ellipse.
  // In SVG arc terms, going clockwise from b around through 0 to a means we
  // need a path from theta=b to theta=2π+a. We split into two arcs to keep things sane.
  const a = Math.PI + 0.1506;
  const b = 2 * Math.PI - 0.1506;

  // Arc from b to 2π (= 0)
  const arc1 = ringPathArc(b, 2 * Math.PI);
  // Arc from 0 to a (which is just π+0.15)
  const arc2 = ringPathArc(0, a);

  const offset = (tick / 12000) * 200;

  return (
    <g>
      {[arc1, arc2].map((d, idx) => (
        <g key={idx}>
          <path d={d} fill="none" stroke="#5ee0ff" strokeWidth="6"
                opacity="0.18" filter="url(#sf-glow)" />
          <path d={d} fill="none" stroke="url(#sf-ring-stroke)" strokeWidth="1.6"
                opacity="0.85" strokeDasharray="3 4" strokeDashoffset={-offset} />
          <path d={d} fill="none" stroke="#cef5ff" strokeWidth="0.5" opacity="0.6" />
        </g>
      ))}
    </g>
  );
}

function Pulse({ p, cycle, t }) {
  return (
    <g pointerEvents="none">
      <circle cx={p.x} cy={p.y} r="58" fill="url(#sf-pulse)" opacity="0.95" />
      <circle cx={p.x} cy={p.y} r="9" fill="#cef5ff"
              style={{ filter: 'drop-shadow(0 0 12px #5ee0ff)' }} />
      {/* Hash fragment riding the pulse */}
      <text x={p.x} y={p.y - 26} textAnchor="middle" className="sf-pulse-hash">
        {shortHash(cycle * 7 + Math.floor(t * 100))}
      </text>
    </g>
  );
}

function EyeFlash({ verdict, phase }) {
  // Locate the eyes on the avatar and overlay a colored bloom that
  // syncs with the verdict. Coordinates are calibrated to where the
  // eyes appear in the cropped avatar at our placed dimensions.
  const eyeY = TEX_Y + TEX_H * 0.165; // ~16.5% from top of avatar
  const eyeLeftX = TEX_X + TEX_W * 0.405;
  const eyeRightX = TEX_X + TEX_W * 0.555;
  const color =
    verdict === 'permit'  ? '#6fdca5' :
    verdict === 'abstain' ? '#ffb547' :
    verdict === 'forbid'  ? '#ff5b5b' : '#5ee0ff';

  return (
    <g aria-hidden="true" className={`sf-eye-flash sf-phase-${phase || 'idle'}`} pointerEvents="none">
      <ellipse cx={eyeLeftX}  cy={eyeY} rx="14" ry="3.2" fill={color} opacity="0.65" filter="url(#sf-glow-sm)" />
      <ellipse cx={eyeRightX} cy={eyeY} rx="14" ry="3.2" fill={color} opacity="0.65" filter="url(#sf-glow-sm)" />
    </g>
  );
}

/* ─── Station node + card ─────────────────────────────────────────── */

function StationNode({ station, index, active, hovered, onHover, onLeave, tick, cycle, counters, verdict }) {
  const cp = cardPosition(station);
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
      {/* Ring node — pip at the station's position on the ring */}
      <circle cx={station.x} cy={station.y} r="4.5"
              fill="#04060c" stroke="#5ee0ff" strokeWidth="1.6" />
      {active && (
        <>
          <circle cx={station.x} cy={station.y} r="9" fill="#cef5ff" opacity="0.95" />
          <circle cx={station.x} cy={station.y} r="14" fill="none"
                  stroke="#9af0ff" strokeWidth="1.4" opacity="0.8">
            <animate attributeName="r" from="8" to="28" dur="0.9s" repeatCount="1" />
            <animate attributeName="opacity" from="0.8" to="0" dur="0.9s" repeatCount="1" />
          </circle>
        </>
      )}

      {/* Card */}
      <g transform={`translate(${cp.bx}, ${cp.by})`}>
        {/* Card backdrop with subtle glow on active */}
        {active && (
          <rect x="-2" y="-2" width={CARD_W + 4} height={CARD_H + 4} rx="3"
                fill="none" stroke="#5ee0ff" strokeWidth="0.8" opacity="0.4"
                filter="url(#sf-glow)" />
        )}
        <rect x="0" y="0" width={CARD_W} height={CARD_H} rx="2"
              fill="url(#sf-card-fill)"
              stroke={active ? '#5ee0ff' : hovered ? '#2fb8e0' : '#1a1f30'}
              strokeWidth={active ? 1.4 : 0.9}
              style={{ transition: 'all 220ms cubic-bezier(0.16,1,0.3,1)' }} />

        {/* Header */}
        <text x="12" y="16" className="sf-card-eyebrow">
          {station.n}
          <tspan className="sf-card-name" dx="6">{station.name}</tspan>
        </text>
        <line x1="12" y1="22" x2={CARD_W - 12} y2="22"
              stroke={active ? '#5ee0ff' : '#1a1f30'}
              strokeWidth="0.6" opacity={active ? 0.85 : 0.4} />

        {/* Body */}
        <g transform="translate(12, 28)">
          <Body w={CARD_W - 24} h={CARD_H - 32}
                tick={tick} cycle={cycle}
                counters={counters} verdict={verdict} />
        </g>

        {/* Active corner brackets */}
        {active && (
          <>
            <path d={`M0,8 L0,0 L8,0`}    stroke="#5ee0ff" strokeWidth="1.4" fill="none" />
            <path d={`M${CARD_W - 8},0 L${CARD_W},0 L${CARD_W},8`}    stroke="#5ee0ff" strokeWidth="1.4" fill="none" />
            <path d={`M0,${CARD_H - 8} L0,${CARD_H} L8,${CARD_H}`}    stroke="#5ee0ff" strokeWidth="1.4" fill="none" />
            <path d={`M${CARD_W - 8},${CARD_H} L${CARD_W},${CARD_H} L${CARD_W},${CARD_H - 8}`} stroke="#5ee0ff" strokeWidth="1.4" fill="none" />
          </>
        )}
      </g>
    </g>
  );
}

/* ─── Per-layer body micro-animations ─────────────────────────────── */

const STATION_BODIES = {
  discovery: ({ w, h, tick }) => {
    const c = Math.floor(tick / 900);
    const agents = [
      'copilot-studio-fa3', 'bedrock-a91x', 'mcp:cursor-12',
      'agentforce-03', 'oai-asst-71', 'graph-share',
      'github-rl3', 'einstein-44', 'amelia-cs',
    ];
    const rows = [];
    for (let i = 0; i < 3; i++) {
      const a = agents[(c + i) % agents.length];
      const isNew = i === 2;
      rows.push(
        <g key={i} transform={`translate(0, ${i * 16})`}>
          <circle cx="3" cy="6" r="2" fill={isNew ? '#9af0ff' : '#4a5060'} />
          <text x="11" y="9" className={`sf-row ${isNew ? 'sf-row-new' : ''}`}>{a}</text>
          {isNew && <text x={w - 2} y="9" textAnchor="end" className="sf-row-tag">NEW</text>}
        </g>
      );
    }
    return (
      <g>
        {rows}
        <text x="0" y={h - 2} className="sf-card-foot">7 connectors · 2,847 found</text>
      </g>
    );
  },

  registration: ({ w, h, tick }) => {
    const c = Math.floor(tick / 1100);
    const states = [
      { id: 'agent-04',   life: 'ACTIVE'  },
      { id: 'support-12', life: 'ACTIVE'  },
      { id: 'fa3-studio', life: 'PENDING' },
    ];
    const flashIdx = c % states.length;
    return (
      <g>
        {states.map((s, i) => {
          const lifeClr = s.life === 'PENDING' ? '#ffb547' : '#6fdca5';
          return (
            <g key={i} transform={`translate(0, ${i * 16})`} opacity={i === flashIdx ? 1 : 0.7}>
              <text x="0" y="9" className="sf-row">{s.id}</text>
              <rect x={w - 56} y="1" width="56" height="11" rx="1"
                    fill="rgba(0,0,0,0.4)" stroke={lifeClr} strokeWidth="0.6" />
              <text x={w - 28} y="10" textAnchor="middle" className="sf-row-life" fill={lifeClr}>{s.life}</text>
            </g>
          );
        })}
        <text x="0" y={h - 2} className="sf-card-foot">2,535 active · 312 held</text>
      </g>
    );
  },

  capability: ({ w, h, tick }) => {
    const cx = w / 2;
    const cy = (h - 14) / 2;
    const rOuter = Math.min(cx, cy) - 2;
    const breath = (Math.sin(tick / 700) * 0.08) + 0.92;
    const rays = 12;
    const lines = [];
    for (let i = 0; i < rays; i++) {
      const a = (i / rays) * Math.PI * 2;
      const allowed = [0, 1, 2, 3, 5, 6, 8, 9].includes(i);
      const len = (allowed ? rOuter * (0.7 + (i % 3) * 0.1) : rOuter * 0.35) * breath;
      lines.push(
        <line key={i} x1={cx} y1={cy}
              x2={cx + Math.cos(a) * len}
              y2={cy + Math.sin(a) * len}
              stroke={allowed ? '#5ee0ff' : '#ff5b5b'}
              strokeWidth="1"
              opacity={allowed ? 0.9 : 0.6} />
      );
    }
    return (
      <g>
        <circle cx={cx} cy={cy} r={rOuter} fill="none" stroke="#1a1f30" strokeWidth="0.5" />
        {lines}
        <circle cx={cx} cy={cy} r="2" fill="#cef5ff" />
        <text x="0" y={h - 2} className="sf-card-foot">surface · 23 cells bound</text>
      </g>
    );
  },

  evaluation: ({ w, h, tick, verdict }) => {
    const cx = w - 18;
    const cy = (h - 14) / 2;
    const flashIdx = Math.floor(tick / 200) % 7;
    const verdictColor = verdict === 'forbid'  ? '#ff5b5b' :
                         verdict === 'abstain' ? '#ffb547' :
                         verdict === 'permit'  ? '#6fdca5' : '#5ee0ff';
    const streams = [];
    for (let i = 0; i < 7; i++) {
      const y = (i / 6) * (h - 18);
      streams.push(
        <line key={i} x1="0" y1={y} x2={cx - 8} y2={cy}
              stroke={i === flashIdx ? '#9af0ff' : '#2fb8e0'}
              strokeWidth={i === flashIdx ? 1.2 : 0.5}
              opacity={i === flashIdx ? 1 : 0.5} />
      );
    }
    return (
      <g>
        {streams}
        <circle cx={cx} cy={cy} r="7" fill="rgba(0,0,0,0.5)" stroke={verdictColor} strokeWidth="1.4" />
        <circle cx={cx} cy={cy} r="2.8" fill={verdictColor} />
        <text x="0" y={h - 2} className="sf-card-foot">7 streams · fused · 2.4ms</text>
      </g>
    );
  },

  enforcement: ({ w, h, tick }) => {
    const examples = [
      { line: 'wire $12,400 → vendor-91', v: 'forbid' },
      { line: 'email lead@acme.io',       v: 'permit' },
      { line: 'sharepoint.share public',  v: 'forbid' },
      { line: 'refund r_42 · $48',        v: 'permit' },
      { line: 'dm @external.client',      v: 'abstain'},
    ];
    const c = Math.floor(tick / 1500);
    const e = examples[c % examples.length];
    const vColor = e.v === 'forbid' ? '#ff5b5b' : e.v === 'abstain' ? '#ffb547' : '#6fdca5';
    return (
      <g>
        <text x="0" y="10" className="sf-row" style={{ fontSize: 10 }}>{e.line}</text>
        <rect x="0" y="18" width={w} height="18" fill="rgba(0,0,0,0.4)" stroke="#1a1f30" strokeWidth="0.6" />
        <line x1={w * 0.6} y1="18" x2={w * 0.6} y2="36" stroke={vColor} strokeWidth="1.5" />
        <circle cx={w * 0.28} cy="27" r="3" fill={vColor} />
        <text x={w * 0.78} y="30" textAnchor="middle" className="sf-row" fill={vColor} style={{ fontWeight: 600, letterSpacing: '0.18em', fontSize: 10 }}>
          {e.v.toUpperCase()}
        </text>
        <text x="0" y={h - 2} className="sf-card-foot">gate · fail-closed · 1.4ms</text>
      </g>
    );
  },

  evidence: ({ w, h, tick }) => {
    const c = Math.floor(tick / 700);
    const offset = (tick / 700) % 1;
    const rows = [];
    for (let i = 0; i < 3; i++) {
      const seed = c - i;
      const hash = hashFragment(seed);
      const y = i * 15 + offset * 15;
      const op = 1 - (i / 3) * 0.7;
      rows.push(
        <g key={i} transform={`translate(0, ${y})`} opacity={op}>
          <text x="0" y="9" className="sf-row-mono">{hash.slice(0, 6)}..{hash.slice(-4)}</text>
          {i < 2 && <text x={w - 2} y="9" textAnchor="end" className="sf-row-dim">←</text>}
        </g>
      );
    }
    return (
      <g>
        <clipPath id="sf-evid-clip-2">
          <rect x="-2" y="-4" width={w + 4} height={h - 16} />
        </clipPath>
        <g clipPath="url(#sf-evid-clip-2)">{rows}</g>
        <text x="0" y={h - 2} className="sf-card-foot">chain sealed · 0 gaps</text>
      </g>
    );
  },

  learning: ({ w, h, tick }) => {
    const POINTS = 18;
    const data = [];
    for (let i = 0; i < POINTS; i++) {
      const x = (i / (POINTS - 1)) * w;
      const phase = (tick / 800) - i * 0.3;
      const y = (h - 18) / 2 + Math.sin(phase) * 5 + Math.sin(phase * 0.5) * 3;
      data.push(`${i === 0 ? 'M' : 'L'}${x.toFixed(1)},${y.toFixed(1)}`);
    }
    const recal = (tick % 4500) < 600;
    return (
      <g>
        <line x1="0" y1={(h - 18) / 2} x2={w} y2={(h - 18) / 2}
              stroke="#1a1f30" strokeWidth="0.5" strokeDasharray="2 4" />
        <path d={data.join(' ')} fill="none" stroke="#5ee0ff" strokeWidth="1.2" opacity="0.9" />
        {recal && <text x={w} y="10" textAnchor="end" className="sf-row-tag" fill="#ffb547">↻ recalibrated</text>}
        <text x="0" y={h - 2} className="sf-card-foot">drift · ▲0.005 permit_t</text>
      </g>
    );
  },
};

function LoopCloseBadge({ tick, cycle }) {
  const phaseInCycle = (tick % CYCLE_MS) / CYCLE_MS;
  const visible = phaseInCycle < 0.13;
  const opacity = visible ? Math.max(0, 1 - (phaseInCycle / 0.13)) : 0;
  return (
    <div className="sf-loop-badge" style={{ opacity }}>
      <span className="lcb-bar" />
      <span className="lcb-text">
        LOOP CLOSED · cycle {String(cycle).padStart(4, '0')} · chain sealed{' '}
        <span className="lcb-hash">{shortHash(cycle * 31)}</span>
      </span>
      <span className="lcb-bar" />
    </div>
  );
}
