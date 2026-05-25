import React, { useEffect, useState, useMemo } from 'react';

/* =============================================================
   ECOSYSTEM RING — six-layer authority arc that sits above Tex.

   Visual model
   ------------
   A wide elliptical arc spans roughly one-sixth to five-sixths
   of the viewport width and crests above the avatar. The six
   ecosystem layers are placed evenly along the arc. A traveling
   pulse moves layer-to-layer; each node lights up as the pulse
   arrives, then dims as it leaves. Execution Governance (layer
   04) is the spine of the product so it gets a stronger glow,
   a larger node, and a longer dwell when active.

   Each layer carries one sentence of description, derived from
   the actual capability tier in CAPABILITY_TIERS.md.
   ============================================================= */

export const ECOSYSTEM_LAYERS = [
  {
    n: '01',
    key: 'discovery',
    name: 'Discovery',
    short: 'Discovery',
    sentence: 'Find every AI agent, MCP server, and tool in your stack.',
  },
  {
    n: '02',
    key: 'identity',
    name: 'Identity',
    short: 'Identity',
    sentence: 'Bind every agent to a cryptographic actor and owner.',
  },
  {
    n: '03',
    key: 'monitoring',
    name: 'Observability',
    short: 'Observability',
    sentence: 'Watch behavior, drift, and systemic risk in real time.',
  },
  {
    n: '04',
    key: 'execution',
    name: 'Execution Governance',
    short: 'Execution',
    sentence: 'Adjudicate every action: permit, abstain, or forbid — before it runs.',
    emphasis: true,
  },
  {
    n: '05',
    key: 'evidence',
    name: 'Evidence',
    short: 'Evidence',
    sentence: 'Seal each decision into a signed, replayable evidence chain.',
  },
  {
    n: '06',
    key: 'learning',
    name: 'Evolution',
    short: 'Evolution',
    sentence: 'Calibrate from sealed outcomes — human-approved, never auto-applied.',
  },
];

/* Sequencing constants — dwell per node, with a longer beat
   on the emphasized Execution Governance layer. */
const BASE_DWELL_MS = 1700;
const EMPHASIS_DWELL_MS = 2700;

function dwellFor(layer) {
  return layer.emphasis ? EMPHASIS_DWELL_MS : BASE_DWELL_MS;
}

export default function EcosystemRing() {
  const [active, setActive] = useState(0);

  /* Sequential layer cycle. Each step waits dwellFor(currentLayer)
     before advancing, so layer 04 holds longer than the rest. */
  useEffect(() => {
    const id = setTimeout(() => {
      setActive((i) => (i + 1) % ECOSYSTEM_LAYERS.length);
    }, dwellFor(ECOSYSTEM_LAYERS[active]));
    return () => clearTimeout(id);
  }, [active]);

  /* Geometry — a shallow arc that hangs across the top of the
     hero like a wireframe halo. The arc itself spans most of the
     viewport width but stays in the upper band, so Tex's head and
     body never collide with it.

     Math choices (locked):
     - VB_H = 260: tall enough for arc (60-200) + label band (top 60px)
     - cy = 380, ry = 280: gives a shallow curve where crest is at
       y ≈ 100 and endpoints at y ≈ 200, total arc rise of only ~100px
     - rx = 760: paired with the 100° angular span, places endpoints
       at x ≈ 218 / 1382 in the 1600-wide viewBox, leaving ~220px
       on each side for label text
     - ARC 220-320: 100° span symmetric about the crest at 270°

     Labels sit OUTWARD from the arc: for top nodes that's straight up,
     for side nodes that's diagonally up-and-out. They never extend
     downward (which would intrude into Tex's portrait area).
  */
  const VB_W = 1600;
  const VB_H = 260;
  const cx = 800;
  const cy = 380;
  const rx = 760;
  const ry = 280;

  /* Angular distribution.
     270° = top of ellipse (= crest of visible arc).
     228° to 312° gives an 84° span symmetric around the crest.
     Tighter than a full 100° because the leftmost and rightmost
     nodes carry descriptions that extend horizontally into the
     margin — pulling the endpoints inward keeps those descriptions
     inside the viewport even at 1440px viewport widths where the
     SVG scales down to ~90% of its native viewBox size. */
  const ARC_START = 232;
  const ARC_END = 308;
  const nodePoints = useMemo(() => {
    const n = ECOSYSTEM_LAYERS.length;
    return ECOSYSTEM_LAYERS.map((layer, i) => {
      const t = n === 1 ? 0.5 : i / (n - 1);
      const angleDeg = ARC_START + t * (ARC_END - ARC_START);
      const rad = (angleDeg * Math.PI) / 180;
      const x = cx + rx * Math.cos(rad);
      const y = cy + ry * Math.sin(rad);
      return { x, y, angleDeg, layer };
    });
  }, []);

  /* Pulse position — sits on the active node. */
  const pulse = nodePoints[active];

  return (
    <div className="er-wrap" aria-hidden="false">
      <svg
        className="er-svg"
        viewBox={`0 0 ${VB_W} ${VB_H}`}
        preserveAspectRatio="xMidYMid meet"
        role="img"
        aria-label="Six-layer ecosystem ring with Discovery, Identity, Monitoring, Execution Governance, Evidence, and Learning"
      >
        <defs>
          {/* Gradient for the main arc — fades in at the ends so it
              feels like it continues off-screen rather than being
              clipped. */}
          <linearGradient id="er-arc-grad" x1="0" y1="0" x2="1" y2="0">
            <stop offset="0%"   stopColor="rgba(86,230,220,0)" />
            <stop offset="14%"  stopColor="rgba(86,230,220,0.45)" />
            <stop offset="50%"  stopColor="rgba(127,241,233,0.85)" />
            <stop offset="86%"  stopColor="rgba(86,230,220,0.45)" />
            <stop offset="100%" stopColor="rgba(86,230,220,0)" />
          </linearGradient>
          <linearGradient id="er-arc-inner" x1="0" y1="0" x2="1" y2="0">
            <stop offset="0%"   stopColor="rgba(86,230,220,0)" />
            <stop offset="20%"  stopColor="rgba(127,241,233,0.18)" />
            <stop offset="50%"  stopColor="rgba(127,241,233,0.55)" />
            <stop offset="80%"  stopColor="rgba(127,241,233,0.18)" />
            <stop offset="100%" stopColor="rgba(86,230,220,0)" />
          </linearGradient>

          {/* Soft glow filter for node halos */}
          <filter id="er-glow" x="-100%" y="-100%" width="300%" height="300%">
            <feGaussianBlur stdDeviation="6" result="b" />
            <feMerge>
              <feMergeNode in="b" />
              <feMergeNode in="SourceGraphic" />
            </feMerge>
          </filter>

          {/* Stronger glow filter reserved for the emphasized node */}
          <filter id="er-glow-strong" x="-100%" y="-100%" width="300%" height="300%">
            <feGaussianBlur stdDeviation="12" result="b" />
            <feMerge>
              <feMergeNode in="b" />
              <feMergeNode in="SourceGraphic" />
            </feMerge>
          </filter>
        </defs>

        {/* === Arc geometry ===
            Two layered ellipse strokes — outer is the visible arc,
            inner is a subtle inner luminance. We render the full
            ellipse but use stroke-dasharray to mask everything
            outside the working arc range, giving us a clean fade. */}
        {(() => {
          // circumference of an ellipse is approximated by Ramanujan's
          // formula; precise enough for visual dash math.
          const h = Math.pow((rx - ry) / (rx + ry), 2);
          const circumference =
            Math.PI * (rx + ry) * (1 + (3 * h) / (10 + Math.sqrt(4 - 3 * h)));
          // Visible arc = (ARC_END - ARC_START) / 360 fraction
          const arcFraction = (ARC_END - ARC_START) / 360;
          const visibleLen = circumference * arcFraction;
          // We need to rotate the start of the dash to ARC_START.
          // The browser draws strokes starting at angle 0 (3 o'clock),
          // going clockwise. Our ARC_START in our math system is 200°
          // (below-left), and our angles increase clockwise too.
          // Offset = -ARC_START fraction of circumference.
          const startOffset = (ARC_START / 360) * circumference;

          return (
            <>
              <ellipse
                cx={cx} cy={cy} rx={rx} ry={ry}
                fill="none"
                stroke="url(#er-arc-grad)"
                strokeWidth="1.4"
                strokeDasharray={`${visibleLen} ${circumference}`}
                strokeDashoffset={-startOffset}
                className="er-arc-outer"
              />
              <ellipse
                cx={cx} cy={cy} rx={rx - 6} ry={ry - 6}
                fill="none"
                stroke="url(#er-arc-inner)"
                strokeWidth="0.8"
                strokeDasharray={`${visibleLen * 0.96} ${circumference}`}
                strokeDashoffset={-startOffset}
                className="er-arc-inner"
              />
            </>
          );
        })()}

        {/* Tick marks along the active arc — small subdivisions
            between the six layer nodes, for a "control panel"
            texture. */}
        {(() => {
          const ticks = 48;
          const arcSpan = ARC_END - ARC_START;
          return Array.from({ length: ticks }).map((_, i) => {
            const t = i / (ticks - 1);
            const angleDeg = ARC_START + t * arcSpan;
            const rad = (angleDeg * Math.PI) / 180;
            const inset = 8;
            const x1 = cx + (rx - inset) * Math.cos(rad);
            const y1 = cy + (ry - inset) * Math.sin(rad);
            const x2 = cx + (rx + inset) * Math.cos(rad);
            const y2 = cy + (ry + inset) * Math.sin(rad);
            const isMajor = i % 8 === 0;
            return (
              <line
                key={`tick-${i}`}
                x1={x1} y1={y1} x2={x2} y2={y2}
                className={`er-tick ${isMajor ? 'er-tick-major' : ''}`}
              />
            );
          });
        })()}

        {/* Traveling pulse — a luminous halo that snaps to the
            active node and pulses there before the next handover.
            We animate the snap via CSS transition on cx/cy. */}
        <g
          className="er-pulse"
          style={{
            transform: `translate(${pulse.x}px, ${pulse.y}px)`,
          }}
        >
          <circle r="36" className="er-pulse-outer" />
          <circle r="20" className="er-pulse-mid" />
          <circle r="9"  className="er-pulse-core" />
        </g>

        {/* Six layer nodes — each renders its glyph cluster and
            the label group anchored above the node. */}
        {nodePoints.map(({ x, y, angleDeg, layer }, i) => {
          const isActive = i === active;
          const isEmphasis = !!layer.emphasis;
          const cls = [
            'er-node',
            isActive ? 'is-active' : '',
            isEmphasis ? 'is-emphasis' : '',
          ].filter(Boolean).join(' ');

          // Compute label position.
          // Strategy: every label sits ABOVE its node by a fixed
          // vertical distance, plus a horizontal nudge based on which
          // side of the arc the node lives on. This guarantees:
          //  - labels never sit below their node (would intrude on Tex)
          //  - labels never overlap the arc curve itself (the lift
          //    clears the arc thickness easily)
          //  - top nodes get the same lift as side nodes for visual
          //    consistency
          const rad = (angleDeg * Math.PI) / 180;
          const cosA = Math.cos(rad);
          // Vertical lift — slightly more for the emphasized node so
          // the two-line label and larger glyph all read cleanly.
          const vertLift = isEmphasis ? 68 : 52;
          // Horizontal nudge — push left-side labels left, right-side
          // labels right, top-center labels barely move. The nudge is
          // small (12-18px) because we rely on text-anchor for direction.
          const horizNudge = cosA * (isEmphasis ? 20 : 16);
          const lx = x + horizNudge;
          const ly = y - vertLift;

          // Anchor handling — left side labels right-align (extend
          // leftward), right side left-align (extend rightward), top
          // labels center-align.
          let anchor = 'middle';
          if (cosA < -0.18) anchor = 'end';
          else if (cosA > 0.18) anchor = 'start';

          // The emphasized node uses a hexagon glyph; the rest use
          // concentric circles. Hex echoes the Tex chest emblem and
          // signals "this is the core."
          return (
            <g key={layer.key} className={cls}>
              {/* Node halo — only renders when active, scaled up on emphasis */}
              <circle
                cx={x} cy={y}
                r={isEmphasis ? 32 : 22}
                className="er-node-halo"
                filter={isEmphasis ? 'url(#er-glow-strong)' : 'url(#er-glow)'}
              />

              {/* Node body */}
              {isEmphasis ? (
                <Hexagon cx={x} cy={y} r={14} className="er-node-hex" />
              ) : (
                <>
                  <circle cx={x} cy={y} r="10" className="er-node-outer" />
                  <circle cx={x} cy={y} r="4"  className="er-node-inner" />
                </>
              )}

              {/* Label cluster — number + name always visible.
                  Description ONLY renders for the active node. This
                  prevents the descriptions of adjacent layers from
                  visually colliding when several long sentences would
                  otherwise extend horizontally into each other.
                  As a bonus, the sequential pulse reveal feels like
                  a guided tour: each layer surfaces its purpose as
                  the pulse arrives, then settles back. */}
              <text
                x={lx} y={ly - 26}
                textAnchor={anchor}
                className="er-label-num"
              >
                /{layer.n}
              </text>
              {isEmphasis ? (
                <text
                  x={lx} y={ly - 6}
                  textAnchor={anchor}
                  className="er-label-name er-label-name--em"
                >
                  <tspan x={lx} dy="0">EXECUTION</tspan>
                  <tspan x={lx} dy="1.1em">GOVERNANCE</tspan>
                </text>
              ) : (
                <text
                  x={lx} y={ly}
                  textAnchor={anchor}
                  className="er-label-name"
                >
                  {layer.name.toUpperCase()}
                </text>
              )}
              {isActive && (
                <text
                  x={lx} y={ly + (isEmphasis ? 36 : 22)}
                  textAnchor={anchor}
                  className="er-label-desc"
                >
                  {layer.sentence}
                </text>
              )}
            </g>
          );
        })}
      </svg>
    </div>
  );
}

/* Small inline hex for the emphasized Execution Governance node.
   Echoes the chest emblem on the Tex avatar. */
function Hexagon({ cx, cy, r, className }) {
  const points = [];
  for (let i = 0; i < 6; i++) {
    const a = (Math.PI / 3) * i - Math.PI / 2; // point-up hex
    points.push(`${cx + r * Math.cos(a)},${cy + r * Math.sin(a)}`);
  }
  return <polygon points={points.join(' ')} className={className} />;
}
