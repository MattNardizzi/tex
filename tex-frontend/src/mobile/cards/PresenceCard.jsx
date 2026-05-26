import React, { useEffect, useState } from 'react';
import Orb from '../../components/Orb.jsx';
import './PresenceCard.css';

/* =============================================================
   PRESENCE CARD — I see them all.

   Discovery + Identity, collapsed into one demonstration that
   matches how a phone holds attention: ONE thing at a time.

   The desktop tells this story as a fan in space — eight agent
   names arc around the orb. A phone has no room for that.

   So on mobile, the same idea becomes a story in TIME. The orb
   sits at the visual center. Below it is a single name slot.
   Eight real connector names from src/tex/discovery/connectors/
   pass through that slot, one at a time, each held for a beat,
   each softly cross-fading into the next. As each name passes,
   a tiny tick joins a row beneath — a tally of identified agents
   accumulating in front of you.

   When the eighth name dissolves, the row settles to "8 IDENTIFIED"
   in mono, and the closing serif sentence resolves:

     "I see them all. I know who they are."

   The orb has not moved. That stillness is the point: Tex is
   surveying its surroundings without ever leaving its post.
   ============================================================= */

const AGENTS = [
  'aws.bedrock',
  'github',
  'microsoft.graph',
  'openai.assistants',
  'openai.live',
  'salesforce',
  'slack',
  'slack.live',
];

const ENTRY_DELAY_MS = 350;
const PER_NAME_MS = 540;          // stagger between name appearances
const SENTENCE_DELAY = ENTRY_DELAY_MS + AGENTS.length * PER_NAME_MS + 600;

export default function PresenceCard({ isActive }) {
  const [armed, setArmed] = useState(false);

  useEffect(() => {
    if (!isActive) return;
    setArmed(false);
    const t = setTimeout(() => setArmed(true), 80);
    return () => clearTimeout(t);
  }, [isActive]);

  return (
    <div className={`tex-presence-card${armed ? ' tex-presence-card--armed' : ''}`}>
      <div className="tex-presence-card-stage">
        <div className="tex-presence-card-orb">
          <Orb state="quiet" size="md" />
        </div>

        {/* The name slot — one fixed-height row where names appear
            one at a time. Each name has its own animation-delay so
            the sequence reads as Tex identifying each thing it sees. */}
        <div className="tex-presence-card-slot" aria-hidden="true">
          {AGENTS.map((agent, i) => (
            <span
              key={agent}
              className="tex-presence-card-name"
              style={{
                animationDelay: `${ENTRY_DELAY_MS + i * PER_NAME_MS}ms`,
                animationDuration: `${PER_NAME_MS}ms`,
              }}
            >
              {agent}
            </span>
          ))}
        </div>

        {/* The accumulating tally — eight tiny vertical ticks that
            light up one by one as each name passes through the slot.
            By the end, all eight are lit. The number to the right
            counts up to 8 and the label settles to IDENTIFIED. */}
        <div className="tex-presence-card-tally" aria-hidden="true">
          <div className="tex-presence-card-ticks">
            {AGENTS.map((_, i) => (
              <span
                key={i}
                className="tex-presence-card-tick"
                style={{ transitionDelay: `${ENTRY_DELAY_MS + i * PER_NAME_MS + 120}ms` }}
              />
            ))}
          </div>
          <div className="tex-presence-card-count">
            <span
              className="tex-presence-card-count-num"
              style={{ transitionDelay: `${SENTENCE_DELAY - 400}ms` }}
            >{AGENTS.length}</span>
            <span
              className="tex-presence-card-count-label"
              style={{ transitionDelay: `${SENTENCE_DELAY - 200}ms` }}
            >IDENTIFIED</span>
          </div>
        </div>

        <p
          className="tex-presence-card-line"
          style={{ transitionDelay: `${SENTENCE_DELAY}ms` }}
        >
          I see them all. <em>I know who they are.</em>
        </p>
      </div>

      <p className="tex-sr-only">
        Tex discovers every AI agent in your environment — across AWS Bedrock,
        GitHub, Microsoft Graph, OpenAI Assistants, OpenAI Live, Salesforce,
        and Slack — and verifies the identity of each.
      </p>
    </div>
  );
}
