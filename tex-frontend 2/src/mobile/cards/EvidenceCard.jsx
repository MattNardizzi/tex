import React, { useEffect, useState } from 'react';
import Orb from '../../components/Orb.jsx';
import './EvidenceCard.css';

/* =============================================================
   EVIDENCE CARD — Every decision, signed.   [MOBILE-NATIVE]

   Desktop: 10-link horizontal chain with branch-down to bundle.
   Mobile:  A DECK OF EVIDENCE CARDS.

   The composition
   ───────────────
   • The orb at top in 'proof' posture, very still.
   • Beneath it, a stack of cards FANNED slightly — each card
     is a signed decision with a mono hash, a timestamp tick,
     and a tiny verdict mark (PERMIT / ABSTAIN / FORBID).
   • The cards auto-cycle: the top card slides off to reveal
     the next one, every ~900ms. By the end, the user has
     watched five decisions move past.
   • Beneath the deck, the BUNDLE.ZIP mark and the proof line.

   Why this works on a phone
   ─────────────────────────
   • A deck of cards is a phone-native metaphor (Tinder, Apple
     Wallet, Stocks). The user immediately understands "many
     things, one at a time."
   • Each card occupies meaningful screen real estate — the
     mono hash is at READABLE size, not 9pt squint.
   • The shuffle conveys "stream" and "signed and signed and
     signed" without showing all ten at once.
   ============================================================= */

const DECK = [
  { hash: '7f3a9b2c…', verdict: 'PERMIT',  ts: '14:02:17.041', note: 'agent.deploy' },
  { hash: 'd84e1f06…', verdict: 'ABSTAIN', ts: '14:02:17.118', note: 'tool.invoke' },
  { hash: '91bf6e5d…', verdict: 'FORBID',  ts: '14:02:17.203', note: 'wire.urgent' },
  { hash: '5a7c1b40…', verdict: 'PERMIT',  ts: '14:02:17.299', note: 'data.read'   },
  { hash: 'f1d829ae…', verdict: 'PERMIT',  ts: '14:02:17.412', note: 'agent.spawn' },
];

const CYCLE_MS = 1100;
const ENTRY_MS = 350;

export default function EvidenceCard({ isActive }) {
  const [armed, setArmed] = useState(false);
  const [top, setTop] = useState(0);

  useEffect(() => {
    if (!isActive) {
      setArmed(false);
      setTop(0);
      return;
    }
    const arm = setTimeout(() => setArmed(true), 80);
    let interval;
    const start = setTimeout(() => {
      interval = setInterval(() => {
        setTop((t) => (t + 1) % DECK.length);
      }, CYCLE_MS);
    }, ENTRY_MS + 1200);
    return () => {
      clearTimeout(arm);
      clearTimeout(start);
      if (interval) clearInterval(interval);
    };
  }, [isActive]);

  return (
    <div className={`tex-m-evidence${armed ? ' tex-m-evidence--armed' : ''}`}>
      <div className="tex-m-evidence-stage">
        <div className="tex-m-evidence-orb">
          <Orb state="proof" size="sm" />
        </div>

        {/* THE DECK — five cards, fanned. The one whose
            position in the deck array matches `top` is the
            currently-visible one; the others sit behind,
            slightly offset and dimmed. */}
        <div className="tex-m-evidence-deck" aria-hidden="true">
          {DECK.map((d, i) => {
            // Compute distance from top in the cycle.
            const dist = (i - top + DECK.length) % DECK.length;
            // dist 0 = on top; 1, 2, 3, 4 = behind in order.
            const isTop = dist === 0;
            const depth = dist;
            return (
              <div
                key={i}
                className={`tex-m-evidence-tile${isTop ? ' tex-m-evidence-tile--top' : ''}`}
                style={{
                  zIndex: DECK.length - dist,
                  transform: `
                    translate(${depth * 6}px, ${depth * 6}px)
                    rotate(${depth * 1.2}deg)
                    scale(${1 - depth * 0.03})
                  `,
                  opacity: depth > 3 ? 0 : 1 - depth * 0.18,
                }}
              >
                <div className="tex-m-evidence-tile-head">
                  <span className={`tex-m-evidence-verdict tex-m-evidence-verdict--${d.verdict.toLowerCase()}`}>
                    {d.verdict}
                  </span>
                  <span className="tex-m-evidence-ts">{d.ts}</span>
                </div>
                <p className="tex-m-evidence-hash">{d.hash}</p>
                <p className="tex-m-evidence-note">{d.note}</p>
                <div className="tex-m-evidence-tile-foot">
                  <span className="tex-m-evidence-sigil" />
                  <span className="tex-m-evidence-signed">SIGNED · POST-QUANTUM</span>
                </div>
              </div>
            );
          })}
        </div>

        {/* BUNDLE mark — the deck rolls up into this. */}
        <div className="tex-m-evidence-bundle">
          <svg width="14" height="11" viewBox="0 0 14 11" fill="none" aria-hidden="true">
            <path
              d="M 1 2 L 5 2 L 7 4 L 13 4 L 13 10 L 1 10 Z"
              fill="none"
              stroke="#14110d"
              strokeWidth="1"
              strokeLinejoin="round"
            />
          </svg>
          <span className="tex-m-evidence-bundle-label">BUNDLE.ZIP — verifiable offline</span>
        </div>

        <p className="tex-m-evidence-line">
          Every decision, signed.{' '}
          <em>Any one of these, verifiable without us.</em>
        </p>
      </div>

      <p className="tex-sr-only">
        Every decision Tex makes produces a signed evidence record, hash-chained
        to every record before it. Bundles are offline-verifiable using
        post-quantum signatures and shaped for regulator delivery.
      </p>
    </div>
  );
}
