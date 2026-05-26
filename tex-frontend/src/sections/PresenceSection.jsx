import React, { useEffect, useRef, useState } from 'react';
import Orb from '../components/Orb.jsx';
import './PresenceSection.css';

/* =============================================================
   PRESENCE — I see them all.

   Discovery and Identity collapsed into one demonstration. The
   buyer doesn't experience them as two systems — they experience
   them as Tex knowing what's in their environment, and knowing
   what each thing is.

   The screen: the orb at center, breathing. Around it, eight
   agents resolve one by one — real connector names from the
   discovery/ package, set in small monospace. As each appears,
   a thin hairline draws from the orb to that agent. The hairlines
   are the act of identification. By the end, eight identified
   agents sit in an arc around Tex. The orb has not moved.

   One serif italic line resolves beneath the composition, only
   after the last hairline completes:

     "I see them all. I know who they are."
   ============================================================= */

// Eight real connectors from src/tex/discovery/connectors/.
// Arranged in a symmetric upper-half-circle fan around the orb,
// so the composition reads as Tex surveying its surroundings.
// Angles measured from the orb center: -180° is hard left, 0° is
// straight up, +180° is hard right. (Custom convention.)
const AGENTS = [
  { name: 'aws.bedrock',          angle: -90 },
  { name: 'github',               angle: -64 },
  { name: 'microsoft.graph',      angle: -38 },
  { name: 'openai.assistants',    angle: -13 },
  { name: 'openai.live',          angle:  13 },
  { name: 'salesforce',           angle:  38 },
  { name: 'slack',                angle:  64 },
  { name: 'slack.live',           angle:  90 },
];

// Geometry — orb sits at the bottom of an arc. Agents sit on a
// circle of radius R. The hairline draws from the orb's edge
// (radius R0) to the agent's leading edge (radius R - R1).
const R   = 320;   // arc radius
const R0  = 70;    // inner gap from orb center
const R1  = 22;    // agent label width radius

const ENTRY_DELAY_MS  = 350;
const PER_AGENT_MS    = 380;
const LINE_REVEAL_MS  = ENTRY_DELAY_MS + AGENTS.length * PER_AGENT_MS + 600;

export default function PresenceSection() {
  const sectionRef = useRef(null);
  const [armed, setArmed] = useState(false);

  useEffect(() => {
    const node = sectionRef.current;
    if (!node) return;
    const io = new IntersectionObserver(
      ([entry]) => {
        if (entry.isIntersecting) {
          setArmed(true);
          io.disconnect();
        }
      },
      { threshold: 0.32 }
    );
    io.observe(node);
    return () => io.disconnect();
  }, []);

  return (
    <section
      ref={sectionRef}
      className={`tex-presence-section${armed ? ' tex-presence-section--armed' : ''}`}
      id="presence"
      aria-label="Discovery and identity — Tex sees every agent and knows what each one is"
    >
      <div className="tex-presence-stage">
        {/* The composition — orb + arc + hairlines. */}
        <div className="tex-presence-composition">
          <svg
            className="tex-presence-svg"
            viewBox="-470 -380 940 440"
            preserveAspectRatio="xMidYMid meet"
            aria-hidden="true"
          >
            {/* Hairlines — drawn first so they sit under the labels.
                Custom angle: 0 = straight up, ±90 = sides. */}
            {AGENTS.map((agent, i) => {
              const rad = ((agent.angle - 90) * Math.PI) / 180;
              const x1 = Math.cos(rad) * R0;
              const y1 = Math.sin(rad) * R0;
              const x2 = Math.cos(rad) * (R - R1);
              const y2 = Math.sin(rad) * (R - R1);
              const delay = ENTRY_DELAY_MS + i * PER_AGENT_MS;
              return (
                <line
                  key={`line-${agent.name}`}
                  className="tex-presence-line"
                  x1={x1} y1={y1}
                  x2={x2} y2={y2}
                  stroke="#5B6E84"
                  strokeOpacity="0.32"
                  strokeWidth="0.6"
                  style={{ animationDelay: `${delay}ms` }}
                />
              );
            })}

            {/* Agent labels — each as a real machine identifier in mono. */}
            {AGENTS.map((agent, i) => {
              const rad = ((agent.angle - 90) * Math.PI) / 180;
              const x = Math.cos(rad) * R;
              const y = Math.sin(rad) * R;
              const delay = ENTRY_DELAY_MS + i * PER_AGENT_MS + 180;

              // Determine text anchor based on the agent's horizontal
              // position — left side anchor right, right side anchor left.
              const cosA = Math.cos(rad);
              const anchor =
                Math.abs(cosA) < 0.15 ? 'middle'
                : cosA < 0            ? 'end'
                                      : 'start';

              const dx = anchor === 'middle' ? 0 : (cosA < 0 ? -6 : 6);

              return (
                <g
                  key={`label-${agent.name}`}
                  className="tex-presence-agent"
                  style={{ animationDelay: `${delay}ms` }}
                  transform={`translate(${x}, ${y})`}
                >
                  {/* tiny mark dot */}
                  <circle
                    cx="0" cy="0"
                    r="2.4"
                    fill="#5B6E84"
                    opacity="0.86"
                  />
                  <text
                    className="tex-presence-agent-label"
                    x={dx} y="4"
                    textAnchor={anchor}
                    fontFamily="var(--tex-mono)"
                    fontSize="10"
                    letterSpacing="0.04em"
                    fill="#5e564c"
                  >
                    {agent.name}
                  </text>
                </g>
              );
            })}
          </svg>

          {/* The orb — DOM, not SVG, so it can breathe with its
              own CSS keyframes. Positioned absolutely at the
              composition's center. */}
          <div className="tex-presence-orb">
            <Orb state="quiet" size="md" />
          </div>
        </div>

        {/* The sentence — resolves only after the last agent settles. */}
        <p
          className="tex-presence-line-text"
          style={{ transitionDelay: `${LINE_REVEAL_MS}ms` }}
        >
          I see them all. <em>I know who they are.</em>
        </p>
      </div>

      <p className="tex-sr-only">
        Tex discovers every AI agent in your environment — across AWS Bedrock,
        GitHub, Microsoft Graph, OpenAI Assistants, OpenAI Live, Salesforce,
        and Slack — and verifies the identity of each.
      </p>
    </section>
  );
}
