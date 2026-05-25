import React, { useEffect, useMemo, useState, useCallback } from 'react';

/* =============================================================
   ECOSYSTEM RING — 360° governance perimeter that encircles Tex.

   v2 design upgrades
   ------------------
   - Removed per-label numeric prefixes (/01, /02…); labels are
     now pure typography arcing the perimeter.
   - Three concentric instrument layers: outer telemetry ring
     (degree markings), middle bezel (graticule), inner main ring.
   - Cardinal crosshair markers at 0/90/180/270 of the outermost
     ring — aviation HUD cue.
   - Label hover state lights up its node, spoke, and the
     corresponding perimeter arc segment. Cursor pointer.
   - Activity pings now do TWO things in tandem: travel down the
     spoke to the hub AND emit a luminous arc that propagates
     ~75° around the perimeter from the node. This signals "any
     layer can adjudicate at any moment AND the perimeter is one
     fused system, not six independent silos."
   - Subtle conic shimmer overlay rotates over the whole ring,
     suggesting live telemetry without distracting from Tex.
   - All animation respects prefers-reduced-motion.
   ============================================================= */

export const ECOSYSTEM_LAYERS = [
  {
    n: '01',
    key: 'discovery',
    name: 'Discovery',
    bearing: 270,
    fontSize: 34,
    sentence: 'Find every AI agent, MCP server, and tool in your stack.',
  },
  {
    n: '02',
    key: 'identity',
    name: 'Identity',
    bearing: 330,
    fontSize: 34,
    sentence: 'Bind every agent to a cryptographic actor and owner.',
  },
  {
    n: '03',
    key: 'observability',
    name: 'Observability',
    bearing: 30,
    fontSize: 26,
    sentence: 'Watch behavior, drift, and systemic risk in real time.',
  },
  {
    n: '04',
    key: 'execution',
    name: 'Execution',
    bearing: 90,
    fontSize: 34,
    sentence: 'Adjudicate every action: permit, abstain, or forbid — before it runs.',
    emphasis: true,
  },
  {
    n: '05',
    key: 'evidence',
    name: 'Evidence',
    bearing: 150,
    fontSize: 34,
    sentence: 'Seal each decision into a signed, replayable evidence chain.',
  },
  {
    n: '06',
    key: 'evolution',
    name: 'Evolution',
    bearing: 210,
    fontSize: 34,
    sentence: 'Calibrate from sealed outcomes — human-approved, never auto-applied.',
  },
];

/* Geometry. The SVG viewBox is square and the ring is centered
   inside. Tex sits behind the SVG, so the ring's interior must
   be visually empty enough for the avatar to read clearly. */
const VB = 1000;
const CX = VB / 2;
const CY = VB / 2;
/* Ring sized to fully encircle Tex's figure. Tex's chest emblem
   sits at the SVG center; his head extends up to ~y=200, his
   shoulders out to ~x=200/800. Ring at R_MAIN=460 means EXECUTION
   at the bottom (y=960) clears his torso entirely. */
const R_MAIN     = 460; // main ring — engraved with layer names
const R_NODE     = 418; // node markers — just inside the ring
const R_BEZEL_OUT = 520;
const R_BEZEL_IN  = 490;
const R_TELEM    = 555; // outermost telemetry ring; bleeds past viewBox (overflow visible)
const R_HUB      = 56;

/* Six segments, 60° each. Each segment is centered on its
   node's bearing. The segment boundaries fall at the midpoints
   between adjacent nodes. The engraved text occupies 50° of the
   60°, leaving ~5° flanks for ring-stroke "endcaps" that frame
   the text. */
const SEG_SPAN     = 60;   // degrees per segment
const TEXT_SPAN    = 50;   // arc-degrees reserved for the engraved text
const BOUNDARY_GAP = 1;    // hairline gap at each segment boundary

function pointAt(radius, bearingDeg) {
  const rad = (bearingDeg * Math.PI) / 180;
  return { x: CX + radius * Math.cos(rad), y: CY + radius * Math.sin(rad) };
}

/* Build an SVG arc path from one bearing to another along a circle.
   Used by the perimeter pulse so we can animate stroke-dashoffset
   along a sweeping arc segment. */
function arcPath(radius, startDeg, endDeg) {
  const start = pointAt(radius, startDeg);
  const end   = pointAt(radius, endDeg);
  const delta = ((endDeg - startDeg) % 360 + 360) % 360;
  const largeArc = delta > 180 ? 1 : 0;
  return `M ${start.x} ${start.y} A ${radius} ${radius} 0 ${largeArc} 1 ${end.x} ${end.y}`;
}

/* For a segment centered on `centerDeg` with full span SEG_SPAN,
   compute:
     - textPath: arc the layer name rides on (direction-corrected
       so text reads upright on both top and bottom halves)
     - leftStroke / rightStroke: the two ring-stroke arc segments
       that flank the engraved text, with hairline gaps at the
       segment boundaries
   The text occupies TEXT_SPAN degrees centered on the segment;
   the strokes fill the remaining arc on either side, minus a
   small BOUNDARY_GAP at each segment boundary so adjacent
   segments don't visually merge. */
function segmentGeometry(centerDeg, radius) {
  const c = ((centerDeg % 360) + 360) % 360;
  const isBottomHalf = c > 0 && c < 180;

  const halfSeg  = SEG_SPAN / 2;
  const halfText = TEXT_SPAN / 2;

  // Segment boundaries
  const segStart = centerDeg - halfSeg + BOUNDARY_GAP;
  const segEnd   = centerDeg + halfSeg - BOUNDARY_GAP;

  // Text arc (direction-corrected so text rides upright)
  const tStart = isBottomHalf ? centerDeg + halfText : centerDeg - halfText;
  const tEnd   = isBottomHalf ? centerDeg - halfText : centerDeg + halfText;
  const tSweep = isBottomHalf ? 0 : 1;
  const tA = pointAt(radius, tStart);
  const tB = pointAt(radius, tEnd);
  const textPath =
    `M ${tA.x} ${tA.y} A ${radius} ${radius} 0 0 ${tSweep} ${tB.x} ${tB.y}`;

  // Two flanking stroke arcs (always CW, sweep=1) — these are
  // visual decoration so direction doesn't need to match text.
  // A small visual padding around the text gives the engraved
  // letters air rather than slamming into the stroke ends.
  const pad = 3;
  const leftA  = pointAt(radius, segStart);
  const leftB  = pointAt(radius, centerDeg - halfText - pad);
  const rightA = pointAt(radius, centerDeg + halfText + pad);
  const rightB = pointAt(radius, segEnd);

  const leftStroke  =
    `M ${leftA.x} ${leftA.y} A ${radius} ${radius} 0 0 1 ${leftB.x} ${leftB.y}`;
  const rightStroke =
    `M ${rightA.x} ${rightA.y} A ${radius} ${radius} 0 0 1 ${rightB.x} ${rightB.y}`;

  // Boundary divider — short radial tick at each segment boundary
  // Returned as the two outer boundary bearings of this segment.
  const boundaries = [
    centerDeg - halfSeg,
    centerDeg + halfSeg,
  ];

  return { textPath, leftStroke, rightStroke, boundaries };
}

export default function EcosystemRing() {
  /* Activity pings — every ~2.6s a random node fires.
     Each ping carries (index, tick) so React can key fresh
     SMIL animations even when the same node fires twice in a row. */
  const [ping, setPing]   = useState({ index: 3, tick: 0 });
  const [hover, setHover] = useState(null); // hovered node index, or null

  useEffect(() => {
    const reduced = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    if (reduced) return;
    const id = setInterval(() => {
      setPing((p) => {
        let next;
        do {
          const bias = Math.random() < 0.28 ? 3 : Math.floor(Math.random() * 6);
          next = bias;
        } while (next === p.index && Math.random() < 0.6);
        return { index: next, tick: p.tick + 1 };
      });
    }, 2600);
    return () => clearInterval(id);
  }, []);

  /* Hovering a label gives the user a feeling of "this is alive
     and I can poke it." Manually firing a ping on hover (debounced
     by the tick increment) avoids waiting for the next interval. */
  const handleLabelEnter = useCallback((i) => {
    setHover(i);
    setPing((p) => ({ index: i, tick: p.tick + 1 }));
  }, []);
  const handleLabelLeave = useCallback(() => setHover(null), []);

  const nodes = useMemo(
    () =>
      ECOSYSTEM_LAYERS.map((layer) => {
        const p   = pointAt(R_NODE, layer.bearing);
        const seg = segmentGeometry(layer.bearing, R_MAIN);
        return { ...layer, ...p, seg };
      }),
    []
  );

  /* Unique boundary bearings across all six segments (de-duplicated).
     Each appears twice in nodes[].seg.boundaries (once as a segment
     end, once as the adjacent segment start) so we Set() them. */
  const segmentBoundaries = useMemo(() => {
    const set = new Set();
    nodes.forEach((n) =>
      n.seg.boundaries.forEach((b) => set.add(((b % 360) + 360) % 360))
    );
    return Array.from(set);
  }, [nodes]);

  return (
    <div className="er-wrap" aria-hidden="false">
      <svg
        className="er-svg"
        viewBox={`0 0 ${VB} ${VB}`}
        preserveAspectRatio="xMidYMid meet"
        role="img"
        aria-label="360° governance ring: Discovery, Identity, Observability, Execution Governance, Evidence, and Evolution encircling Tex."
      >
        <defs>
          {/* Main ring gradient — luminous at the Execution anchor */}
          <linearGradient id="er-main-grad" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%"   stopColor="rgba(86,230,220,0.55)" />
            <stop offset="50%"  stopColor="rgba(127,241,233,0.75)" />
            <stop offset="100%" stopColor="rgba(127,241,233,1)" />
          </linearGradient>

          {/* Radar sweep cone */}
          <radialGradient id="er-sweep-grad" cx="0.5" cy="0.5" r="0.5">
            <stop offset="0%"   stopColor="rgba(127,241,233,0.32)" />
            <stop offset="55%"  stopColor="rgba(86,230,220,0.16)" />
            <stop offset="100%" stopColor="rgba(86,230,220,0)" />
          </radialGradient>

          {/* Spoke gradient — fades inward */}
          <linearGradient id="er-spoke-grad" x1="0" y1="0" x2="1" y2="0">
            <stop offset="0%"   stopColor="rgba(86,230,220,0.0)" />
            <stop offset="60%"  stopColor="rgba(86,230,220,0.18)" />
            <stop offset="100%" stopColor="rgba(127,241,233,0.55)" />
          </linearGradient>

          {/* Conic shimmer overlay — a barely-there cyan flare that
              orbits the ring, suggesting live telemetry */}
          <radialGradient id="er-shimmer" cx="0.5" cy="0.5" r="0.5">
            <stop offset="0%"   stopColor="rgba(127,241,233,0)" />
            <stop offset="70%"  stopColor="rgba(127,241,233,0)" />
            <stop offset="100%" stopColor="rgba(127,241,233,0.12)" />
          </radialGradient>

          {/* Glow filters */}
          <filter id="er-glow-soft" x="-50%" y="-50%" width="200%" height="200%">
            <feGaussianBlur stdDeviation="6" result="b" />
            <feMerge>
              <feMergeNode in="b" />
              <feMergeNode in="SourceGraphic" />
            </feMerge>
          </filter>
          <filter id="er-glow-strong" x="-100%" y="-100%" width="300%" height="300%">
            <feGaussianBlur stdDeviation="14" result="b" />
            <feMerge>
              <feMergeNode in="b" />
              <feMergeNode in="SourceGraphic" />
            </feMerge>
          </filter>
          <filter id="er-glow-arc" x="-50%" y="-50%" width="200%" height="200%">
            <feGaussianBlur stdDeviation="4" result="b" />
            <feMerge>
              <feMergeNode in="b" />
              <feMergeNode in="SourceGraphic" />
            </feMerge>
          </filter>

          {/* Sweep arm wedge */}
          {(() => {
            const span = 55;
            const r = R_MAIN + 30;
            const a0 = (-span * Math.PI) / 180;
            const x0 = CX + r * Math.cos(a0);
            const y0 = CY + r * Math.sin(a0);
            const x1 = CX + r;
            const y1 = CY;
            return (
              <path
                id="er-sweep-wedge"
                d={`M ${CX},${CY} L ${x0},${y0} A ${r},${r} 0 0 1 ${x1},${y1} Z`}
              />
            );
          })()}

          {/* Per-segment text baselines — each layer's name rides
              along this arc. Direction-corrected so bottom-half
              labels read upright. */}
          {nodes.map((node) => (
            <path
              key={`textpath-${node.key}`}
              id={`er-text-${node.key}`}
              d={node.seg.textPath}
              fill="none"
            />
          ))}

          {/* Full-circle path on the main ring — particles ride this
              clockwise to suggest continuous data flow through the
              perimeter. Drawn as two semicircles because a single
              full-circle path can't be expressed with one arc cmd. */}
          <path
            id="er-particle-orbit"
            d={`M ${CX - R_MAIN} ${CY}
                A ${R_MAIN} ${R_MAIN} 0 1 1 ${CX + R_MAIN} ${CY}
                A ${R_MAIN} ${R_MAIN} 0 1 1 ${CX - R_MAIN} ${CY}`}
            fill="none"
          />
        </defs>

        {/* ============================================================
            OUTERMOST TELEMETRY RING — degree marks every 30°
            with 000°/030°/060°… labels. Aviation HUD cue.
            ============================================================ */}
        <g className="er-telem">
          <circle
            cx={CX}
            cy={CY}
            r={R_TELEM}
            fill="none"
            stroke="rgba(86,230,220,0.10)"
            strokeWidth="0.5"
          />
          {Array.from({ length: 12 }).map((_, i) => {
            const angle = i * 30; // SVG bearing
            const rad = (angle * Math.PI) / 180;
            const inner = R_TELEM - 8;
            const outer = R_TELEM + 4;
            const x1 = CX + inner * Math.cos(rad);
            const y1 = CY + inner * Math.sin(rad);
            const x2 = CX + outer * Math.cos(rad);
            const y2 = CY + outer * Math.sin(rad);
            return (
              <line
                key={`telem-tick-${i}`}
                x1={x1} y1={y1} x2={x2} y2={y2}
                stroke="rgba(127,241,233,0.45)"
                strokeWidth="1.1"
              />
            );
          })}
        </g>

        {/* Cardinal crosshair markers — small + glyphs at N/E/S/W
            of the outermost telemetry ring */}
        <g className="er-cardinals">
          {[0, 90, 180, 270].map((a) => {
            const rad = (a * Math.PI) / 180;
            const r = R_TELEM + 18;
            const x = CX + r * Math.cos(rad);
            const y = CY + r * Math.sin(rad);
            return (
              <g key={`card-cross-${a}`} transform={`translate(${x} ${y})`}>
                <line x1="-5" y1="0" x2="5" y2="0"
                  stroke="rgba(127,241,233,0.55)" strokeWidth="1" />
                <line x1="0" y1="-5" x2="0" y2="5"
                  stroke="rgba(127,241,233,0.55)" strokeWidth="1" />
              </g>
            );
          })}
        </g>

        {/* ============================================================
            OUTER BEZEL — dashed circle + graticule ticks, spins CW
            ============================================================ */}
        <g className="er-bezel er-bezel--outer">
          <circle
            cx={CX} cy={CY} r={R_BEZEL_OUT}
            fill="none"
            stroke="rgba(86,230,220,0.22)"
            strokeWidth="0.8"
            strokeDasharray="2 8"
          />
          {Array.from({ length: 60 }).map((_, i) => {
            const angle = i * 6;
            const isMajor = angle % 30 === 0;
            const rad = (angle * Math.PI) / 180;
            const r1 = R_BEZEL_OUT - (isMajor ? 14 : 6);
            const r2 = R_BEZEL_OUT - 1;
            return (
              <line
                key={`tick-out-${i}`}
                x1={CX + r1 * Math.cos(rad)}
                y1={CY + r1 * Math.sin(rad)}
                x2={CX + r2 * Math.cos(rad)}
                y2={CY + r2 * Math.sin(rad)}
                className={`er-tick ${isMajor ? 'er-tick--major' : ''}`}
              />
            );
          })}
        </g>

        {/* Inner bezel: hairline, counter-rotates */}
        <g className="er-bezel er-bezel--inner">
          <circle
            cx={CX} cy={CY} r={R_BEZEL_IN}
            fill="none"
            stroke="rgba(86,230,220,0.18)"
            strokeWidth="0.6"
          />
          {[0, 90, 180, 270].map((a) => {
            const rad = (a * Math.PI) / 180;
            const x = CX + R_BEZEL_IN * Math.cos(rad);
            const y = CY + R_BEZEL_IN * Math.sin(rad);
            return (
              <circle
                key={`card-${a}`}
                cx={x} cy={y} r="1.8"
                fill="rgba(127,241,233,0.65)"
              />
            );
          })}
        </g>

        {/* ============================================================
            CONIC SHIMMER — slow rotating cyan flare
            ============================================================ */}
        <g className="er-shimmer">
          <circle cx={CX} cy={CY} r={R_BEZEL_OUT - 10}
            fill="url(#er-shimmer)" opacity="0.5" />
        </g>

        {/* ============================================================
            SWEEP ARM — slow radar sweep, one revolution / 24s
            ============================================================ */}
        <g className="er-sweep">
          <use href="#er-sweep-wedge" fill="url(#er-sweep-grad)" />
          <line
            x1={CX} y1={CY}
            x2={CX + R_MAIN + 28} y2={CY}
            className="er-sweep-edge"
          />
        </g>

        {/* ============================================================
            SPOKES — six radial lines, node → hub
            ============================================================ */}
        <g className="er-spokes">
          {nodes.map((node, i) => {
            const inner = pointAt(R_HUB, node.bearing);
            const isLit = ping.index === i || hover === i;
            return (
              <line
                key={`spoke-${node.key}`}
                x1={node.x} y1={node.y}
                x2={inner.x} y2={inner.y}
                stroke="url(#er-spoke-grad)"
                strokeWidth={node.emphasis ? '1.4' : '0.9'}
                className={`er-spoke ${isLit ? 'is-pinging' : ''}`}
              />
            );
          })}
        </g>

        {/* ============================================================
            PINGS — inward dot down the spoke + perimeter arc pulse
            ============================================================ */}
        {nodes.map((node, i) => {
          if (ping.index !== i) return null;
          const inner = pointAt(R_HUB, node.bearing);

          /* Perimeter arc — 75° span centered on this node, drawn
             slightly OUTSIDE the main ring (at R_MAIN+8) so the
             traveling pulse rides the outer edge of the ring and
             doesn't fight the engraved text living on R_MAIN. */
          const arcSpan = 75;
          const arcRadius = R_MAIN + 8;
          const arcStart = node.bearing - arcSpan / 2;
          const arcEnd   = node.bearing + arcSpan / 2;
          const arcCircumference = 2 * Math.PI * arcRadius * (arcSpan / 360);

          return (
            <g key={`ping-${ping.tick}-${node.key}`}>
              {/* Spoke ping — luminous halo + bright core travel inward */}
              <circle r="6" className="er-ping er-ping--halo">
                <animateMotion
                  dur="1.1s"
                  fill="freeze"
                  path={`M ${node.x},${node.y} L ${inner.x},${inner.y}`}
                />
                <animate
                  attributeName="opacity"
                  values="0;1;1;0"
                  keyTimes="0;0.15;0.7;1"
                  dur="1.1s"
                  fill="freeze"
                />
              </circle>
              <circle r="2.6" className="er-ping er-ping--core">
                <animateMotion
                  dur="1.1s"
                  fill="freeze"
                  path={`M ${node.x},${node.y} L ${inner.x},${inner.y}`}
                />
              </circle>

              {/* Perimeter arc pulse — bright segment sweeps the ring */}
              <path
                d={arcPath(arcRadius, arcStart, arcEnd)}
                className="er-arc-pulse"
                fill="none"
                strokeDasharray={arcCircumference}
              >
                <animate
                  attributeName="stroke-dashoffset"
                  from={arcCircumference}
                  to={-arcCircumference}
                  dur="1.4s"
                  fill="freeze"
                />
                <animate
                  attributeName="opacity"
                  values="0;0.95;0.95;0"
                  keyTimes="0;0.12;0.75;1"
                  dur="1.4s"
                  fill="freeze"
                />
              </path>
            </g>
          );
        })}

        {/* ============================================================
            PARTICLE STREAM — eight tiny luminous dots orbit the main
            ring clockwise, each phase-shifted so they're distributed
            evenly. Suggests continuous data flow through the
            perimeter, separate from the discrete node pings.
            ============================================================ */}
        <g className="er-particles" aria-hidden="true">
          {Array.from({ length: 8 }).map((_, i) => {
            const offset = i / 8;
            const dur = 14; // seconds per orbit
            return (
              <circle
                key={`particle-${i}`}
                r="2"
                className="er-particle"
              >
                <animateMotion
                  dur={`${dur}s`}
                  repeatCount="indefinite"
                  begin={`-${offset * dur}s`}
                  rotate="auto"
                >
                  <mpath href="#er-particle-orbit" />
                </animateMotion>
              </circle>
            );
          })}
        </g>

        {/* ============================================================
            MAIN RING — drawn as six segments with engraved text gaps.
            The original continuous circle is replaced by twelve short
            arcs (two flanking arcs per layer segment), with the
            engraved layer name occupying the central arc-degrees of
            each segment. This makes the ring itself read as six
            chambers, one per governance layer.
            ============================================================ */}
        <g className="er-main">
          {/* Soft outer halo — a faint continuous glow ring so the
              perimeter still reads as a single closed system even
              though the bright stroke is broken at the text. */}
          <circle
            cx={CX} cy={CY} r={R_MAIN}
            fill="none"
            stroke="rgba(127,241,233,0.10)"
            strokeWidth="6"
            className="er-main-glow"
          />

          {/* Twelve stroked arc segments — two flanking each layer */}
          {nodes.map((node, i) => {
            const isLit = ping.index === i || hover === i;
            return (
              <g
                key={`mainseg-${node.key}`}
                className={`er-main-seg ${node.emphasis ? 'is-emphasis' : ''} ${isLit ? 'is-lit' : ''}`}
              >
                <path
                  d={node.seg.leftStroke}
                  fill="none"
                  stroke="url(#er-main-grad)"
                  strokeWidth="1.6"
                  strokeLinecap="round"
                  className="er-main-stroke"
                />
                <path
                  d={node.seg.rightStroke}
                  fill="none"
                  stroke="url(#er-main-grad)"
                  strokeWidth="1.6"
                  strokeLinecap="round"
                  className="er-main-stroke"
                />
              </g>
            );
          })}

          {/* Hairline radial dividers at segment boundaries —
              subtle ticks straddling the ring stroke. They mark
              the six chambers without breaking the closed-system
              reading. */}
          {segmentBoundaries.map((b) => {
            const rad = (b * Math.PI) / 180;
            const r1 = R_MAIN - 10;
            const r2 = R_MAIN + 10;
            return (
              <line
                key={`seg-divider-${b}`}
                x1={CX + r1 * Math.cos(rad)}
                y1={CY + r1 * Math.sin(rad)}
                x2={CX + r2 * Math.cos(rad)}
                y2={CY + r2 * Math.sin(rad)}
                stroke="rgba(127,241,233,0.32)"
                strokeWidth="1"
                className="er-seg-divider"
              />
            );
          })}
        </g>

        {/* ============================================================
            HUB — center medallion behind Tex's chest
            ============================================================ */}
        <g className="er-hub">
          <circle
            cx={CX} cy={CY} r={R_HUB}
            fill="none"
            stroke="rgba(86,230,220,0.22)"
            strokeWidth="0.8"
          />
          <circle
            cx={CX} cy={CY} r={R_HUB - 12}
            fill="none"
            stroke="rgba(86,230,220,0.12)"
            strokeWidth="0.6"
            strokeDasharray="3 5"
            className="er-hub-inner"
          />
        </g>

        {/* ============================================================
            NODES — small indicator markers sitting just INSIDE the
            ring. With the layer names now engraved on the ring
            itself, these become subordinate "status dots." Execution
            Governance keeps its hex emblem because it's the
            structural anchor of the whole composition.
            ============================================================ */}
        {nodes.map((node, i) => {
          const isEm     = !!node.emphasis;
          const isActive = ping.index === i;
          const isHover  = hover === i;
          return (
            <g
              key={node.key}
              className={`er-node ${isEm ? 'is-emphasis' : ''} ${isActive ? 'is-pinging' : ''} ${isHover ? 'is-hover' : ''}`}
            >
              <circle
                cx={node.x} cy={node.y}
                r={isEm ? 20 : 12}
                className="er-node-halo"
                filter={isEm ? 'url(#er-glow-strong)' : 'url(#er-glow-soft)'}
              />
              {isEm ? (
                <Hexagon cx={node.x} cy={node.y} r={11} className="er-node-hex" />
              ) : (
                <>
                  <circle cx={node.x} cy={node.y} r="5.5" className="er-node-ring" />
                  <circle cx={node.x} cy={node.y} r="2.2" className="er-node-core" />
                </>
              )}
            </g>
          );
        })}

        {/* ============================================================
            LABELS — engraved on the ring. Each layer name rides
            along its segment's text arc via <textPath>, with the
            stroke broken on either side so the letters sit IN the
            ring (watch-bezel feel). Hover lights the segment up.
            Execution Governance is rendered as TWO words on
            parallel concentric arcs straddling the ring stroke.
            ============================================================ */}
        {nodes.map((node, i) => {
          const isEm    = !!node.emphasis;
          const isLit   = ping.index === i || hover === i;
          const delay   = `${(i * 0.4).toFixed(2)}s`;
          const fontSize = node.fontSize || 34;

          return (
            <g
              key={`label-${node.key}`}
              className={`er-label ${isEm ? 'is-emphasis' : ''} ${isLit ? 'is-hover' : ''}`}
              style={{ '--er-label-delay': delay, cursor: 'pointer' }}
              onMouseEnter={() => handleLabelEnter(i)}
              onMouseLeave={handleLabelLeave}
            >
              {/* Thick invisible hit-strip along the segment arc so
                  the whole curved label region is hoverable, not
                  just the glyphs. */}
              <path
                d={node.seg.textPath}
                fill="none"
                stroke="transparent"
                strokeWidth="80"
                pointerEvents="stroke"
              />

              <text
                className={`er-label-name ${isEm ? 'er-label-name--em' : ''}`}
                style={{ fontSize: `${fontSize}px` }}
                dy="0.35em"
              >
                <textPath
                  href={`#er-text-${node.key}`}
                  startOffset="50%"
                  textAnchor="middle"
                >
                  {node.name.toUpperCase()}
                </textPath>
              </text>
            </g>
          );
        })}
      </svg>
    </div>
  );
}

/* Small point-up hexagon — echoes Tex's chest emblem */
function Hexagon({ cx, cy, r, className }) {
  const points = [];
  for (let i = 0; i < 6; i++) {
    const a = (Math.PI / 3) * i - Math.PI / 2;
    points.push(`${cx + r * Math.cos(a)},${cy + r * Math.sin(a)}`);
  }
  return <polygon points={points.join(' ')} className={className} />;
}
