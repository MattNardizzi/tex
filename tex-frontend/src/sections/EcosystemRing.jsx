import React, { useEffect, useMemo, useState } from 'react';

/* =============================================================
   ECOSYSTEM RING — 360° governance perimeter that encircles Tex.

   Design intent
   -------------
   This is not a process arc. It is a closed instrument ring —
   the visual boundary of the airspace Tex controls. Six layers
   are distributed evenly around the circumference. Execution
   Governance is anchored at 6 o'clock so it forms a structural
   spine with the headline below; the other five fan above and
   to the sides, framing Tex inside the perimeter.

   Visual layers (outside → inside)
   --------------------------------
   1. Bearing labels      — mono-cap layer codes outside the bezel,
                             rotated tangentially so they read like
                             an aircraft compass rose
   2. Outer bezel rings   — two counter-rotating dashed rings with
                             radial graticule ticks, "instrument"
                             texture (HUD/aviation reference)
   3. Main ring           — single luminous stroke through all six
                             nodes, the perimeter itself
   4. Layer nodes         — five circular nodes + one hex anchor
                             (Execution Governance at 6 o'clock)
   5. Radial spokes       — faint lines from each node inward to
                             the ring's center (Tex's chest), so
                             the umbrella reading is explicit
   6. Sweep arm           — slow radar sweep, one revolution every
                             ~24s, gradient fan trailing behind
   7. Activity pings      — random nodes emit a pulse along their
                             spoke every few seconds (asynchronous,
                             not sequential) to signal "all six
                             always-on, simultaneously"

   All animation respects prefers-reduced-motion.
   ============================================================= */

export const ECOSYSTEM_LAYERS = [
  {
    n: '01',
    key: 'discovery',
    name: 'Discovery',
    bearing: 270, // top (12 o'clock)
    sentence: 'Find every AI agent, MCP server, and tool in your stack.',
  },
  {
    n: '02',
    key: 'identity',
    name: 'Identity',
    bearing: 330, // upper-right (2 o'clock)
    sentence: 'Bind every agent to a cryptographic actor and owner.',
  },
  {
    n: '03',
    key: 'observability',
    name: 'Observability',
    bearing: 30,  // lower-right (4 o'clock)
    sentence: 'Watch behavior, drift, and systemic risk in real time.',
  },
  {
    n: '04',
    key: 'execution',
    name: 'Execution Governance',
    bearing: 90,  // bottom (6 o'clock) — anchored, structural spine
    sentence: 'Adjudicate every action: permit, abstain, or forbid — before it runs.',
    emphasis: true,
  },
  {
    n: '05',
    key: 'evidence',
    name: 'Evidence',
    bearing: 150, // lower-left (8 o'clock)
    sentence: 'Seal each decision into a signed, replayable evidence chain.',
  },
  {
    n: '06',
    key: 'evolution',
    name: 'Evolution',
    bearing: 210, // upper-left (10 o'clock)
    sentence: 'Calibrate from sealed outcomes — human-approved, never auto-applied.',
  },
];

/* Geometry. The SVG viewBox is square and the ring is centered
   inside. Tex sits behind the SVG, so the ring's interior must
   be visually empty enough for the avatar to read clearly. */
const VB = 1000;                  // viewBox edge
const CX = VB / 2;
const CY = VB / 2;
const R_MAIN = 400;               // main ring radius (where nodes sit)
const R_BEZEL_OUT = 460;          // outer bezel ring
const R_BEZEL_IN  = 430;          // inner bezel ring (counter-rotates)
const R_LABEL = 488;              // bearing label radius (outside bezel)
const R_HUB = 56;                 // inner hub circle (around Tex's chest emblem)

/* Convert bearing (0° = right, 90° = down, 270° = up, clockwise)
   to SVG (x,y) on the main ring. Standard math convention so the
   data above can use intuitive clock-face values. */
function pointAt(radius, bearingDeg) {
  const rad = (bearingDeg * Math.PI) / 180;
  return { x: CX + radius * Math.cos(rad), y: CY + radius * Math.sin(rad) };
}

export default function EcosystemRing() {
  /* Activity pings — every ~2.6s a random node fires a ping that
     travels along its spoke from the perimeter inward to the hub.
     This signals "all six layers are always-on, simultaneously,
     and any of them can adjudicate at any moment." Asynchronous
     (random) on purpose — sequential pulses re-create the very
     "process arc" reading we are trying to break. */
  const [ping, setPing] = useState({ index: 3, tick: 0 });

  useEffect(() => {
    const reduced = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    if (reduced) return;
    const id = setInterval(() => {
      setPing((p) => {
        // Pick a different node than the last one for visual variety,
        // with a slight bias toward Execution Governance (index 3)
        // because that's our emphasis layer.
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

  /* Pre-compute node geometry once. */
  const nodes = useMemo(
    () =>
      ECOSYSTEM_LAYERS.map((layer) => {
        const p = pointAt(R_MAIN, layer.bearing);
        const pLabel = pointAt(R_LABEL, layer.bearing);
        return { ...layer, ...p, lx: pLabel.x, ly: pLabel.y };
      }),
    []
  );

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
          {/* --- Gradients ----------------------------------- */}

          {/* Main ring gradient — luminous along the bottom (where
              Execution Governance sits) and fading toward the top.
              This biases the eye toward the anchor without breaking
              the closed-ring reading. */}
          <linearGradient id="er-main-grad" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%"   stopColor="rgba(86,230,220,0.55)" />
            <stop offset="50%"  stopColor="rgba(127,241,233,0.75)" />
            <stop offset="100%" stopColor="rgba(127,241,233,1)" />
          </linearGradient>

          {/* Sweep arm — a cone of light trailing the radar arm.
              Bright at the leading edge, fading to nothing. Rendered
              as a path filled with this gradient (radial from center
              outward, masked to a pie wedge). */}
          <radialGradient id="er-sweep-grad" cx="0.5" cy="0.5" r="0.5">
            <stop offset="0%"   stopColor="rgba(127,241,233,0.32)" />
            <stop offset="55%"  stopColor="rgba(86,230,220,0.16)" />
            <stop offset="100%" stopColor="rgba(86,230,220,0)" />
          </radialGradient>

          {/* Spoke gradient — fades inward so the spokes don't
              compete with Tex for attention near the center. */}
          <linearGradient id="er-spoke-grad" x1="0" y1="0" x2="1" y2="0">
            <stop offset="0%"   stopColor="rgba(86,230,220,0.0)" />
            <stop offset="60%"  stopColor="rgba(86,230,220,0.18)" />
            <stop offset="100%" stopColor="rgba(127,241,233,0.55)" />
          </linearGradient>

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

          {/* --- Reusable paths -------------------------------- */}

          {/* Curved path for the top half of the bearing-label ring,
              used as a textPath baseline so labels along the top
              are rendered upright but slightly arched. We don't
              use it for the side/bottom labels (those use rotated
              tspans for legibility). */}
          <path
            id="er-label-arc-top"
            d={`M ${CX - R_LABEL},${CY} A ${R_LABEL},${R_LABEL} 0 0 1 ${CX + R_LABEL},${CY}`}
            fill="none"
          />

          {/* The sweep-arm wedge: a pie slice from center outward
              spanning ~55°. Drawn at 0° rotation; the parent <g>
              spins this around. */}
          {(() => {
            const span = 55; // degrees of the trailing cone
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
        </defs>

        {/* ============================================================
            OUTER BEZEL — two concentric rings + graticule ticks
            ============================================================ */}

        {/* Outer bezel: thin dashed circle, rotates clockwise slowly. */}
        <g className="er-bezel er-bezel--outer">
          <circle
            cx={CX}
            cy={CY}
            r={R_BEZEL_OUT}
            fill="none"
            stroke="rgba(86,230,220,0.22)"
            strokeWidth="0.8"
            strokeDasharray="2 8"
          />
          {/* Major bearing ticks every 30°, minor every 6° */}
          {Array.from({ length: 60 }).map((_, i) => {
            const angle = i * 6;
            const isMajor = angle % 30 === 0;
            const rad = (angle * Math.PI) / 180;
            const r1 = R_BEZEL_OUT - (isMajor ? 14 : 6);
            const r2 = R_BEZEL_OUT - 1;
            const x1 = CX + r1 * Math.cos(rad);
            const y1 = CY + r1 * Math.sin(rad);
            const x2 = CX + r2 * Math.cos(rad);
            const y2 = CY + r2 * Math.sin(rad);
            return (
              <line
                key={`tick-out-${i}`}
                x1={x1}
                y1={y1}
                x2={x2}
                y2={y2}
                className={`er-tick ${isMajor ? 'er-tick--major' : ''}`}
              />
            );
          })}
        </g>

        {/* Inner bezel: solid hairline circle, counter-rotates. */}
        <g className="er-bezel er-bezel--inner">
          <circle
            cx={CX}
            cy={CY}
            r={R_BEZEL_IN}
            fill="none"
            stroke="rgba(86,230,220,0.18)"
            strokeWidth="0.6"
          />
          {/* Cardinal markers — small hairline arrowheads at
              N/E/S/W of the inner bezel. Aviation instrument
              cue. */}
          {[0, 90, 180, 270].map((a) => {
            const rad = (a * Math.PI) / 180;
            const r = R_BEZEL_IN;
            const x = CX + r * Math.cos(rad);
            const y = CY + r * Math.sin(rad);
            return (
              <circle
                key={`card-${a}`}
                cx={x}
                cy={y}
                r="1.8"
                fill="rgba(127,241,233,0.65)"
              />
            );
          })}
        </g>

        {/* ============================================================
            SWEEP ARM — slow radar sweep, one revolution / 24s
            ============================================================ */}
        <g className="er-sweep">
          <use href="#er-sweep-wedge" fill="url(#er-sweep-grad)" />
          {/* The leading edge — a bright thin line at the arm's
              forward angle, with a soft glow */}
          <line
            x1={CX}
            y1={CY}
            x2={CX + R_MAIN + 28}
            y2={CY}
            className="er-sweep-edge"
          />
        </g>

        {/* ============================================================
            SPOKES — six radial lines, node → hub
            ============================================================ */}
        <g className="er-spokes">
          {nodes.map((node, i) => {
            const inner = pointAt(R_HUB, node.bearing);
            return (
              <line
                key={`spoke-${node.key}`}
                x1={node.x}
                y1={node.y}
                x2={inner.x}
                y2={inner.y}
                stroke="url(#er-spoke-grad)"
                strokeWidth={node.emphasis ? '1.4' : '0.9'}
                className={`er-spoke ${ping.index === i ? 'is-pinging' : ''}`}
              />
            );
          })}
        </g>

        {/* ============================================================
            PINGS — a luminous dot travels along the active spoke
            from the perimeter inward. SMIL animateMotion keeps this
            tight in code and frame-perfect; CSS fallback handled by
            prefers-reduced-motion (the interval simply stops firing).
            ============================================================ */}
        {nodes.map((node, i) => {
          if (ping.index !== i) return null;
          const inner = pointAt(R_HUB, node.bearing);
          return (
            <g key={`ping-${ping.tick}-${node.key}`}>
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
            </g>
          );
        })}

        {/* ============================================================
            MAIN RING — the perimeter
            Drawn AFTER spokes so it overpaints the spoke ends cleanly
            at the join. Drawn BEFORE nodes so the nodes sit on top.
            ============================================================ */}
        <g className="er-main">
          <circle
            cx={CX}
            cy={CY}
            r={R_MAIN}
            fill="none"
            stroke="url(#er-main-grad)"
            strokeWidth="1.6"
            className="er-main-stroke"
          />
          {/* Subtle outer glow halo on the main ring */}
          <circle
            cx={CX}
            cy={CY}
            r={R_MAIN}
            fill="none"
            stroke="rgba(127,241,233,0.18)"
            strokeWidth="4"
            className="er-main-glow"
          />
        </g>

        {/* ============================================================
            HUB — small center medallion behind Tex's chest
            ============================================================ */}
        <g className="er-hub">
          <circle
            cx={CX}
            cy={CY}
            r={R_HUB}
            fill="none"
            stroke="rgba(86,230,220,0.22)"
            strokeWidth="0.8"
          />
          <circle
            cx={CX}
            cy={CY}
            r={R_HUB - 12}
            fill="none"
            stroke="rgba(86,230,220,0.12)"
            strokeWidth="0.6"
            strokeDasharray="3 5"
            className="er-hub-inner"
          />
        </g>

        {/* ============================================================
            NODES — six layer markers on the main ring
            ============================================================ */}
        {nodes.map((node, i) => {
          const isEm = !!node.emphasis;
          const isActive = ping.index === i;
          return (
            <g
              key={node.key}
              className={`er-node ${isEm ? 'is-emphasis' : ''} ${isActive ? 'is-pinging' : ''}`}
            >
              {/* Halo */}
              <circle
                cx={node.x}
                cy={node.y}
                r={isEm ? 26 : 18}
                className="er-node-halo"
                filter={isEm ? 'url(#er-glow-strong)' : 'url(#er-glow-soft)'}
              />
              {/* Body */}
              {isEm ? (
                <Hexagon cx={node.x} cy={node.y} r={13} className="er-node-hex" />
              ) : (
                <>
                  <circle cx={node.x} cy={node.y} r="8.5" className="er-node-ring" />
                  <circle cx={node.x} cy={node.y} r="3" className="er-node-core" />
                </>
              )}
            </g>
          );
        })}

        {/* ============================================================
            BEARING LABELS — outside the bezel, oriented along the
            tangent so they read like an instrument compass rose.

            Each label rotates with its bearing so the text always
            sits radially outside its node. We use bearing+90° for
            the rotation so the baseline is along the ring's tangent.
            For nodes in the bottom half (90° area), we additionally
            flip 180° so the text remains right-side-up.
            ============================================================ */}
        {nodes.map((node) => {
          const isEm = !!node.emphasis;

          /* Label placement strategy
             ------------------------
             - Cardinal nodes (Discovery at 270° top, Execution at
               90° bottom) get a centered, upright two-line block —
               number above name (top) or name below number-above-it
               (bottom). No rotation; centered on the node's bearing.
             - Side nodes (Identity, Observability, Evidence,
               Evolution) get a single-line label rotated tangentially
               so it reads along the outside of the ring like an
               aircraft compass scale. We flip 180° for the bottom-half
               side nodes so text stays right-side-up.

             This is more legible than rotating every label, and the
             vertical cardinal labels reinforce the structural spine:
             /01 DISCOVERY at top, /04 EXECUTION GOVERNANCE at bottom.
           */
          const isCardinalTop    = node.bearing === 270;
          const isCardinalBottom = node.bearing === 90;
          const isCardinal       = isCardinalTop || isCardinalBottom;

          if (isCardinal) {
            // Vertical stack, centered on the node's bearing. For the
            // bottom cardinal we put the name BELOW the number so the
            // composition reads ring → hex → /04 → EXECUTION GOVERNANCE
            // → eyebrow → headline — one clean vertical spine.
            const yNum  = isCardinalTop ? -16 : 16;
            const yName = isCardinalTop ? 6   : (isEm ? 40 : 36);
            return (
              <g
                key={`label-${node.key}`}
                className={`er-label ${isEm ? 'is-emphasis' : ''}`}
                transform={`translate(${node.lx} ${node.ly})`}
              >
                <text
                  x={0}
                  y={yNum}
                  textAnchor="middle"
                  className="er-label-num"
                >
                  /{node.n}
                </text>
                {isEm ? (
                  <text
                    x={0}
                    y={yName}
                    textAnchor="middle"
                    className="er-label-name er-label-name--em"
                  >
                    <tspan x={0} dy="0">EXECUTION</tspan>
                    <tspan x={0} dy="1.15em">GOVERNANCE</tspan>
                  </text>
                ) : (
                  <text
                    x={0}
                    y={yName}
                    textAnchor="middle"
                    className="er-label-name"
                  >
                    {node.name.toUpperCase()}
                  </text>
                )}
              </g>
            );
          }

          // Side nodes — tangentially-rotated single-line label.
          let rot = node.bearing + 90;
          const bottomHalf = node.bearing > 0 && node.bearing < 180;
          if (bottomHalf) rot += 180;
          // After rotation, the label's "right" is the outward radial
          // direction; we want the text to extend OUTWARD from the
          // node, so we anchor it at start and offset slightly.
          return (
            <g
              key={`label-${node.key}`}
              className={`er-label ${isEm ? 'is-emphasis' : ''}`}
              transform={`translate(${node.lx} ${node.ly}) rotate(${rot})`}
            >
              <text
                x={0}
                y={-6}
                textAnchor="middle"
                className="er-label-num"
              >
                /{node.n}
              </text>
              <text
                x={0}
                y={12}
                textAnchor="middle"
                className="er-label-name"
              >
                {node.name.toUpperCase()}
              </text>
            </g>
          );
        })}
      </svg>
    </div>
  );
}

/* Small point-up hexagon — echoes the chest emblem on Tex. */
function Hexagon({ cx, cy, r, className }) {
  const points = [];
  for (let i = 0; i < 6; i++) {
    const a = (Math.PI / 3) * i - Math.PI / 2;
    points.push(`${cx + r * Math.cos(a)},${cy + r * Math.sin(a)}`);
  }
  return <polygon points={points.join(' ')} className={className} />;
}
