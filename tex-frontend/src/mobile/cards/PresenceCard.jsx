import React, { useEffect, useState } from 'react';
import Orb from '../../components/Orb.jsx';
import './PresenceCard.css';

/* =============================================================
   PRESENCE CARD — I see them all.   [MOBILE-NATIVE COMPOSITION]

   Desktop: eight agent names arc around the orb in a spatial fan.
   Mobile:  eight agent names RAIN DOWN the screen vertically,
            falling at different speeds. As each one crosses the
            orb's horizon line at center, it LOCKS — the name
            settles into a small constellation around the orb.
            By the end, eight names hold position around Tex.

   Why this works on a phone
   ─────────────────────────
   • Vertical motion uses the phone's portrait orientation. The
     names use the full height as a runway.
   • The rain reads as INPUT — Tex is taking it in. The lock
     reads as RECOGNITION — Tex names what it has seen.
   • Each name has a unique fall path and a unique resting
     position around the orb. Watching it once is enough to
     understand the demonstration; watching it twice is satisfying.

   No desktop site does this. The composition is invented for
   the form factor.
   ============================================================= */

const AGENTS = [
  // Each agent: a name, a fall start-X (% from left), a final
  // resting position around the orb (angle in degrees, radius in px).
  { name: 'aws.bedrock',        x: 18,  delay: 0,    angle: -130, r: 110 },
  { name: 'github',             x: 76,  delay: 220,  angle:  -85, r: 92  },
  { name: 'microsoft.graph',    x: 30,  delay: 440,  angle:  -40, r: 116 },
  { name: 'openai.assistants',  x: 62,  delay: 660,  angle:    8, r: 122 },
  { name: 'openai.live',        x: 24,  delay: 880,  angle:   58, r: 108 },
  { name: 'salesforce',         x: 70,  delay: 1100, angle:  102, r: 116 },
  { name: 'slack',              x: 14,  delay: 1320, angle:  150, r: 90  },
  { name: 'slack.live',         x: 82,  delay: 1540, angle:  195, r: 110 },
];

const FALL_DUR = 1700;
const SETTLE_DUR = 700;
const ENTRY_DELAY = 350;
const LAST_AGENT_DONE = ENTRY_DELAY + AGENTS[AGENTS.length - 1].delay + FALL_DUR + SETTLE_DUR;
const SENTENCE_MS = LAST_AGENT_DONE - 400;

export default function PresenceCard({ isActive }) {
  const [armed, setArmed] = useState(false);

  useEffect(() => {
    if (!isActive) {
      setArmed(false);
      return;
    }
    const t = setTimeout(() => setArmed(true), 80);
    return () => clearTimeout(t);
  }, [isActive]);

  return (
    <div className={`tex-m-presence${armed ? ' tex-m-presence--armed' : ''}`}>
      {/* THE FIELD — falling agents. Each is absolutely
          positioned within this field; it covers the upper
          ~62% of the card. The orb sits at the field's
          bottom center, where the rain lands. */}
      <div className="tex-m-presence-field" aria-hidden="true">
        {AGENTS.map((a, i) => {
          const finalRad = (a.angle * Math.PI) / 180;
          const finalX = Math.cos(finalRad) * a.r;
          const finalY = Math.sin(finalRad) * a.r;
          return (
            <span
              key={a.name}
              className="tex-m-presence-name"
              style={{
                '--start-x': `${a.x}%`,
                '--final-x': `${finalX}px`,
                '--final-y': `${finalY}px`,
                animationDelay: `${ENTRY_DELAY + a.delay}ms`,
              }}
            >
              {a.name}
            </span>
          );
        })}

        {/* The orb at the constellation's center — drawn AFTER
            the names so it occludes them as they arrive. */}
        <div className="tex-m-presence-orb">
          <Orb state="quiet" size="sm" />
        </div>
      </div>

      <p
        className="tex-m-presence-line"
        style={{ transitionDelay: `${SENTENCE_MS}ms` }}
      >
        I see them all. <em>I know who they are.</em>
      </p>

      <p className="tex-sr-only">
        Tex discovers every AI agent in your environment — across AWS Bedrock,
        GitHub, Microsoft Graph, OpenAI Assistants, OpenAI Live, Salesforce,
        and Slack — and verifies the identity of each.
      </p>
    </div>
  );
}
