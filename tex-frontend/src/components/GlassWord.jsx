import { useId } from 'react';
import './GlassWord.css';

/**
 * GlassWord — text rendered in the same blue-gray glass treatment used for
 * "Absolute." on the hero. Same component, same gradient, same light sweep.
 *
 * Body:  vertical gradient F4F6FA → C8D2DE → 5B6E84 → 1D2733
 * Rim:   white highlight that fades by 14% (top edge catching light)
 * Floor: soft elliptical drop shadow
 * Sweep: slow light pass across the letterforms every 7s
 */
export default function GlassWord({
  text,
  fontSize = 42,
  letterSpacing = -1.6,
  width = 240,
  height = 64,
  baseline = 42,
  sweep = true,
}) {
  const uid = useId().replace(/:/g, '');
  const bodyId = `gw-body-${uid}`;
  const rimId = `gw-rim-${uid}`;
  const floorId = `gw-floor-${uid}`;
  const maskId = `gw-mask-${uid}`;

  return (
    <svg
      width={width}
      height={height}
      viewBox={`0 0 ${width} ${height}`}
      style={{ overflow: 'visible', display: 'block' }}
      aria-label={text}
      role="img"
    >
      <defs>
        <linearGradient id={bodyId} x1="0%" y1="0%" x2="0%" y2="100%">
          <stop offset="0%" stopColor="#F4F6FA" stopOpacity="0.98" />
          <stop offset="28%" stopColor="#C8D2DE" stopOpacity="0.92" />
          <stop offset="58%" stopColor="#5B6E84" stopOpacity="0.95" />
          <stop offset="100%" stopColor="#1D2733" stopOpacity="1" />
        </linearGradient>

        <linearGradient id={rimId} x1="0%" y1="0%" x2="0%" y2="100%">
          <stop offset="0%" stopColor="#FFFFFF" stopOpacity="0.85" />
          <stop offset="14%" stopColor="#FFFFFF" stopOpacity="0" />
          <stop offset="100%" stopColor="#FFFFFF" stopOpacity="0" />
        </linearGradient>

        <radialGradient id={floorId} cx="50%" cy="50%" r="50%">
          <stop offset="0%" stopColor="#0E1620" stopOpacity="0.10" />
          <stop offset="60%" stopColor="#0E1620" stopOpacity="0.04" />
          <stop offset="100%" stopColor="#0E1620" stopOpacity="0" />
        </radialGradient>

        {sweep && (
          <mask id={maskId}>
            <text
              x={width / 2}
              y={baseline}
              textAnchor="middle"
              fontFamily="var(--tex-serif)"
              fontSize={fontSize}
              fontWeight="400"
              letterSpacing={letterSpacing}
              fill="#FFFFFF"
            >
              {text}
            </text>
          </mask>
        )}
      </defs>

      <ellipse
        cx={width / 2}
        cy={height - 6}
        rx={width * 0.38}
        ry="3.5"
        fill={`url(#${floorId})`}
      />

      <text
        x={width / 2}
        y={baseline}
        textAnchor="middle"
        fontFamily="var(--tex-serif)"
        fontSize={fontSize}
        fontWeight="400"
        letterSpacing={letterSpacing}
        fill={`url(#${bodyId})`}
      >
        {text}
      </text>

      <text
        x={width / 2}
        y={baseline}
        textAnchor="middle"
        fontFamily="var(--tex-serif)"
        fontSize={fontSize}
        fontWeight="400"
        letterSpacing={letterSpacing}
        fill={`url(#${rimId})`}
      >
        {text}
      </text>

      <text
        x={width / 2}
        y={baseline}
        textAnchor="middle"
        fontFamily="var(--tex-serif)"
        fontSize={fontSize}
        fontWeight="400"
        letterSpacing={letterSpacing}
        fill="none"
        stroke="#5B6E84"
        strokeOpacity="0.35"
        strokeWidth="0.4"
      >
        {text}
      </text>

      {sweep && (
        <g mask={`url(#${maskId})`}>
          <rect
            className="tex-gw-sweep"
            x={-width / 3}
            y="0"
            width={width / 3}
            height={height}
            fill="#E6F0FF"
            style={{ '--tex-gw-end': `${width + width / 3}px` }}
          />
        </g>
      )}
    </svg>
  );
}
