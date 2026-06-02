import React, { useEffect, useRef, useState } from 'react';
import Orb from '../components/Orb.jsx';
import './EvidenceSection.css';

/* =============================================================
   EVIDENCE — Signed. Verifiable without us.

   The moat made visible. Every competitor in the AI agent
   governance category treats recording as a log file. Tex
   produces signed, chained, regulator-shaped evidence — any
   one of which can be verified offline, without ever touching
   Tex's servers. This is the differentiator that wins the
   contract.

   The screen: the orb at top center, held very still (proof
   posture, slower breath). Below it, a chain resolves left to
   right — ten dots, each linked to the next by a hairline. As
   each dot resolves, a small SHA-256 hash flickers and settles
   underneath it in monospace. Real hashes, real chain — this
   is the only place on the page where monospace earns its
   keep, because these are actual machine identifiers.

   After the chain completes, one dot in the middle pulses
   faintly. A single hairline draws from it downward, leaving
   the chain. At its terminus, a small folder mark resolves.
   That's the regulator pulling the bundle and verifying it
   on their own machine.

   Two lines resolve beneath. The serif sentence first; the
   proof line below it.
   ============================================================= */

// Real-looking SHA-256 prefixes. These read as machine truth.
// In production these come from the evidence chain. Here they
// are static representatives — what a buyer would see if they
// opened a bundle.
const CHAIN = [
  '7f3a9b2c',
  'd84e1f06',
  'a2c5b918',
  '4e7d3a02',
  '91bf6e5d',  // the highlighted one — index 4
  'c3a8f274',
  '0b6d4e1a',
  '8e2f9c53',
  '5a7c1b40',
  'f1d829ae',
];

const HIGHLIGHTED_INDEX = 4;

const ENTRY_DELAY_MS = 350;
const PER_LINK_MS = 320;
const CHAIN_DONE_MS = ENTRY_DELAY_MS + CHAIN.length * PER_LINK_MS + 300;
const PULSE_MS = CHAIN_DONE_MS + 200;
const EXPORT_LINE_MS = PULSE_MS + 400;
const FOLDER_MS = EXPORT_LINE_MS + 700;
const SENTENCE_MS = FOLDER_MS + 600;
const PROOF_MS = SENTENCE_MS + 700;

export default function EvidenceSection() {
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
      { threshold: 0.28 }
    );
    io.observe(node);
    return () => io.disconnect();
  }, []);

  // Geometry — the chain sits on a horizontal line beneath the orb.
  // 10 dots evenly spaced across the canvas, with a 6% margin on
  // each side. The export hairline leaves from the highlighted dot
  // and descends to a folder mark below.
  const W = 1000;
  const H = 380;
  const CHAIN_Y = 140;
  const MARGIN_X = 80;
  const SPACING = (W - 2 * MARGIN_X) / (CHAIN.length - 1);
  const xAt = (i) => MARGIN_X + i * SPACING;

  const HIGHLIGHTED_X = xAt(HIGHLIGHTED_INDEX);
  const FOLDER_Y = 320;

  return (
    <section
      ref={sectionRef}
      className={`tex-evidence${armed ? ' tex-evidence--armed' : ''}`}
      id="evidence"
      aria-label="Evidence — every decision is signed and verifiable without us"
    >
      <div className="tex-evidence-stage">
        {/* The orb — held very still in proof posture. */}
        <div className="tex-evidence-orb">
          <Orb state="proof" size="sm" />
        </div>

        {/* MOBILE COMPOSITION — a representative chain, not the full one.
            The desktop drawing shows ten links because density IS the
            point: many decisions, all signed. On a phone, ten dots make
            a tall stripe that crowds the sentence. Instead, five visible
            links — the first two, the highlighted middle, and the last
            two — plus a small "+ N more" indicator suggest the chain
            extends beyond what the eye is given. The chain feels longer
            because the user can't see the end of it.

            The highlighted link still branches sideways to BUNDLE.ZIP.
            The sentence beneath is the same. */}
        <div className="tex-evidence-mobile" aria-hidden="true">
          {(() => {
            // Show the first two links, the highlighted link, and the
            // last two — five visible total. The remaining five are
            // implied by a small counter between the highlighted link
            // and the tail.
            const visible = [
              { hash: CHAIN[0], originalIndex: 0,                          isHighlighted: false },
              { hash: CHAIN[1], originalIndex: 1,                          isHighlighted: false },
              { hash: CHAIN[HIGHLIGHTED_INDEX], originalIndex: HIGHLIGHTED_INDEX, isHighlighted: true  },
              { hash: CHAIN[CHAIN.length - 2], originalIndex: CHAIN.length - 2,   isHighlighted: false },
              { hash: CHAIN[CHAIN.length - 1], originalIndex: CHAIN.length - 1,   isHighlighted: false },
            ];
            const remainingBefore = HIGHLIGHTED_INDEX - 2; // links between visible #2 and highlighted
            const remainingAfter  = CHAIN.length - 1 - HIGHLIGHTED_INDEX - 2; // between highlighted and last two
            return (
              <ol className="tex-evidence-mobile-chain">
                {visible.map((link, i) => {
                  const delay = ENTRY_DELAY_MS + i * PER_LINK_MS;
                  const showGapBefore =
                    (i === 2 && remainingBefore > 0) ||
                    (i === 3 && remainingAfter > 0);
                  const gapCount =
                    i === 2 ? remainingBefore :
                    i === 3 ? remainingAfter  : 0;
                  return (
                    <React.Fragment key={`m-${link.originalIndex}`}>
                      {showGapBefore && (
                        <li
                          className="tex-evidence-mobile-gap"
                          style={{ transitionDelay: `${delay - 100}ms` }}
                          aria-hidden="true"
                        >
                          <span className="tex-evidence-mobile-gap-mark">+ {gapCount}</span>
                        </li>
                      )}
                      <li
                        className={`tex-evidence-mobile-link${link.isHighlighted ? ' tex-evidence-mobile-link--highlighted' : ''}`}
                        style={{ transitionDelay: `${delay}ms` }}
                      >
                        <span className="tex-evidence-mobile-dot" />
                        <span className="tex-evidence-mobile-hash">{link.hash}</span>
                        {link.isHighlighted && (
                          <span
                            className="tex-evidence-mobile-branch"
                            style={{ transitionDelay: `${EXPORT_LINE_MS}ms` }}
                            aria-hidden="true"
                          >
                            <span className="tex-evidence-mobile-branch-line" />
                            <span
                              className="tex-evidence-mobile-bundle"
                              style={{ transitionDelay: `${FOLDER_MS}ms` }}
                            >
                              <svg width="32" height="20" viewBox="0 0 32 20" fill="none" aria-hidden="true">
                                <path
                                  d="M 2 4 L 12 4 L 16 8 L 30 8 L 30 18 L 2 18 Z"
                                  fill="none"
                                  stroke="#14110d"
                                  strokeWidth="1"
                                  strokeLinejoin="round"
                                />
                              </svg>
                              <span className="tex-evidence-mobile-bundle-label">BUNDLE.ZIP</span>
                            </span>
                          </span>
                        )}
                      </li>
                    </React.Fragment>
                  );
                })}
              </ol>
            );
          })()}
        </div>

        <div className="tex-evidence-composition">
          <svg
            className="tex-evidence-svg"
            viewBox={`0 0 ${W} ${H}`}
            preserveAspectRatio="xMidYMid meet"
            aria-hidden="true"
          >
            {/* Hairlines between dots — drawn before dots so they
                sit beneath. Each segment animates after the previous
                dot has appeared. */}
            {CHAIN.slice(0, -1).map((_, i) => {
              const x1 = xAt(i);
              const x2 = xAt(i + 1);
              const delay = ENTRY_DELAY_MS + (i + 1) * PER_LINK_MS - 200;
              return (
                <line
                  key={`seg-${i}`}
                  className="tex-evidence-seg"
                  x1={x1} y1={CHAIN_Y}
                  x2={x2} y2={CHAIN_Y}
                  stroke="#5B6E84"
                  strokeOpacity="0.46"
                  strokeWidth="0.8"
                  style={{ animationDelay: `${delay}ms` }}
                />
              );
            })}

            {/* Dots — each represents a signed decision. The highlighted
                one is slightly larger and gains a soft pulse after the
                chain completes. */}
            {CHAIN.map((hash, i) => {
              const x = xAt(i);
              const delay = ENTRY_DELAY_MS + i * PER_LINK_MS;
              const isHighlighted = i === HIGHLIGHTED_INDEX;
              return (
                <g
                  key={`dot-${i}`}
                  className={`tex-evidence-link${isHighlighted ? ' tex-evidence-link--highlighted' : ''}`}
                  style={{ animationDelay: `${delay}ms` }}
                >
                  {isHighlighted && (
                    <circle
                      className="tex-evidence-pulse"
                      cx={x} cy={CHAIN_Y}
                      r="14"
                      fill="#5B6E84"
                      fillOpacity="0.18"
                      style={{ animationDelay: `${PULSE_MS}ms` }}
                    />
                  )}
                  <circle
                    cx={x} cy={CHAIN_Y}
                    r={isHighlighted ? 5 : 4}
                    fill="#14110d"
                  />
                  <text
                    className="tex-evidence-hash"
                    x={x} y={CHAIN_Y + 26}
                    textAnchor="middle"
                    fontFamily="var(--tex-mono)"
                    fontSize="9"
                    letterSpacing="0.04em"
                    fill="#5e564c"
                  >
                    {hash}
                  </text>
                </g>
              );
            })}

            {/* The export hairline — descends from the highlighted dot
                to the folder mark below. Drawn after the chain completes. */}
            <line
              className="tex-evidence-export-line"
              x1={HIGHLIGHTED_X} y1={CHAIN_Y + 12}
              x2={HIGHLIGHTED_X} y2={FOLDER_Y - 18}
              stroke="#5B6E84"
              strokeOpacity="0.4"
              strokeWidth="0.6"
              strokeDasharray="3 4"
              style={{
                opacity: armed ? 1 : 0,
                transitionDelay: `${EXPORT_LINE_MS}ms`,
              }}
            />

            {/* The folder mark — minimal geometric shape, ink. */}
            <g
              className="tex-evidence-folder"
              style={{
                opacity: armed ? 1 : 0,
                transitionDelay: `${FOLDER_MS}ms`,
              }}
            >
              <path
                d={`M ${HIGHLIGHTED_X - 18} ${FOLDER_Y - 12}
                    L ${HIGHLIGHTED_X - 4} ${FOLDER_Y - 12}
                    L ${HIGHLIGHTED_X + 1} ${FOLDER_Y - 6}
                    L ${HIGHLIGHTED_X + 18} ${FOLDER_Y - 6}
                    L ${HIGHLIGHTED_X + 18} ${FOLDER_Y + 10}
                    L ${HIGHLIGHTED_X - 18} ${FOLDER_Y + 10} Z`}
                fill="none"
                stroke="#14110d"
                strokeWidth="1"
                strokeLinejoin="round"
              />
              <text
                className="tex-evidence-folder-label"
                x={HIGHLIGHTED_X} y={FOLDER_Y + 32}
                textAnchor="middle"
                fontFamily="var(--tex-mono)"
                fontSize="9"
                letterSpacing="0.08em"
                fill="#9b9388"
              >
                BUNDLE.ZIP
              </text>
            </g>
          </svg>
        </div>

        {/* The sentence and the proof line. */}
        <div className="tex-evidence-copy">
          <p
            className="tex-evidence-line"
            style={{ transitionDelay: `${SENTENCE_MS}ms` }}
          >
            Every decision, signed.{' '}
            <em>Any one of these, verifiable without us.</em>
          </p>
          <p
            className="tex-evidence-proof"
            style={{ transitionDelay: `${PROOF_MS}ms` }}
          >
            OFFLINE · POST-QUANTUM · REGULATOR-SHAPED
          </p>
        </div>
      </div>

      <p className="tex-sr-only">
        Every decision Tex makes produces a signed evidence record, hash-chained
        to every record before it. Bundles are offline-verifiable using
        post-quantum signatures and shaped for regulator delivery.
      </p>
    </section>
  );
}
