import React, { useEffect, useState } from 'react';
import Orb from '../../components/Orb.jsx';
import './EvidenceCard.css';

/* =============================================================
   EVIDENCE CARD — Every decision, signed.

   The moat made visible, redesigned for the phone.

   The desktop tells this beat as a horizontal chain — ten dots
   marching across the canvas, the middle one branching down to
   a BUNDLE.ZIP folder. That's the right composition for the
   desktop's wide canvas.

   On a phone, the chain stands up. Five visible links arranged
   vertically along a hairline spine — the first two, the
   highlighted middle (which branches sideways to BUNDLE.ZIP),
   and the last two. Between them, two small "+ N" elision
   marks make the chain feel longer than what's drawn: the user
   doesn't see the end of it.

   The highlighted link pulses softly after the chain completes,
   then branches sideways to the bundle mark. The serif sentence
   and proof line resolve at the bottom.

   Why elision works
   ─────────────────
   Showing ten dots on a phone makes the chain feel CRUSHED.
   Showing five with elision marks makes the chain feel LONG.
   Same idea, different medium.
   ============================================================= */

const CHAIN = [
  { hash: '7f3a9b2c' },
  { hash: 'd84e1f06' },
  { hash: '91bf6e5d', highlighted: true },
  { hash: '5a7c1b40' },
  { hash: 'f1d829ae' },
];

const ENTRY_DELAY_MS = 350;
const PER_LINK_MS = 380;
const CHAIN_DONE_MS = ENTRY_DELAY_MS + CHAIN.length * PER_LINK_MS + 200;
const BRANCH_MS = CHAIN_DONE_MS + 300;
const BUNDLE_MS = BRANCH_MS + 500;
const SENTENCE_MS = BUNDLE_MS + 500;
const PROOF_MS = SENTENCE_MS + 500;

export default function EvidenceCard({ isActive }) {
  const [armed, setArmed] = useState(false);

  useEffect(() => {
    if (!isActive) return;
    setArmed(false);
    const t = setTimeout(() => setArmed(true), 80);
    return () => clearTimeout(t);
  }, [isActive]);

  return (
    <div className={`tex-evidence-card${armed ? ' tex-evidence-card--armed' : ''}`}>
      <div className="tex-evidence-card-stage">
        <div className="tex-evidence-card-orb">
          <Orb state="proof" size="sm" />
        </div>

        {/* THE CHAIN — vertical spine + dots + hashes + elision
            marks. Layout is grid: column 1 is the spine and dots,
            column 2 is the hash and any branch content. */}
        <ol className="tex-evidence-card-chain" aria-hidden="true">
          {/* Link 1 */}
          <li
            className="tex-evidence-card-link"
            style={{ transitionDelay: `${ENTRY_DELAY_MS}ms` }}
          >
            <span className="tex-evidence-card-dot" />
            <span className="tex-evidence-card-hash">{CHAIN[0].hash}</span>
          </li>

          {/* Link 2 */}
          <li
            className="tex-evidence-card-link"
            style={{ transitionDelay: `${ENTRY_DELAY_MS + PER_LINK_MS}ms` }}
          >
            <span className="tex-evidence-card-dot" />
            <span className="tex-evidence-card-hash">{CHAIN[1].hash}</span>
          </li>

          {/* Elision +3 */}
          <li
            className="tex-evidence-card-elide"
            style={{ transitionDelay: `${ENTRY_DELAY_MS + 1.6 * PER_LINK_MS}ms` }}
          >
            <span className="tex-evidence-card-elide-mark">+ 3</span>
          </li>

          {/* Highlighted middle link with branch */}
          <li
            className="tex-evidence-card-link tex-evidence-card-link--highlighted"
            style={{ transitionDelay: `${ENTRY_DELAY_MS + 2 * PER_LINK_MS}ms` }}
          >
            <span className="tex-evidence-card-dot" />
            <span className="tex-evidence-card-hash">{CHAIN[2].hash}</span>
            <span
              className="tex-evidence-card-branch"
              style={{ transitionDelay: `${BRANCH_MS}ms` }}
            >
              <span className="tex-evidence-card-branch-line" />
              <span
                className="tex-evidence-card-bundle"
                style={{ transitionDelay: `${BUNDLE_MS}ms` }}
              >
                <svg width="26" height="18" viewBox="0 0 26 18" fill="none" aria-hidden="true">
                  <path
                    d="M 1 3 L 9 3 L 12 6 L 25 6 L 25 17 L 1 17 Z"
                    fill="none"
                    stroke="#14110d"
                    strokeWidth="1"
                    strokeLinejoin="round"
                  />
                </svg>
                <span className="tex-evidence-card-bundle-label">BUNDLE.ZIP</span>
              </span>
            </span>
          </li>

          {/* Elision +2 */}
          <li
            className="tex-evidence-card-elide"
            style={{ transitionDelay: `${ENTRY_DELAY_MS + 2.6 * PER_LINK_MS}ms` }}
          >
            <span className="tex-evidence-card-elide-mark">+ 2</span>
          </li>

          {/* Link tail */}
          <li
            className="tex-evidence-card-link"
            style={{ transitionDelay: `${ENTRY_DELAY_MS + 3 * PER_LINK_MS}ms` }}
          >
            <span className="tex-evidence-card-dot" />
            <span className="tex-evidence-card-hash">{CHAIN[3].hash}</span>
          </li>
          <li
            className="tex-evidence-card-link"
            style={{ transitionDelay: `${ENTRY_DELAY_MS + 4 * PER_LINK_MS}ms` }}
          >
            <span className="tex-evidence-card-dot" />
            <span className="tex-evidence-card-hash">{CHAIN[4].hash}</span>
          </li>
        </ol>

        <div className="tex-evidence-card-copy">
          <p
            className="tex-evidence-card-line"
            style={{ transitionDelay: `${SENTENCE_MS}ms` }}
          >
            Every decision, signed.{' '}
            <em>Any one of these, verifiable without us.</em>
          </p>
          <p
            className="tex-evidence-card-proof"
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
    </div>
  );
}
