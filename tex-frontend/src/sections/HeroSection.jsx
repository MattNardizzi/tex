import React from 'react';
import texAvatar from '../tex-avatar.png';
import EcosystemRing from './EcosystemRing.jsx';
import './HeroSection.css';

/* =============================================================
   HERO SECTION

   Two-column composition:

     ┌───────────────────────┬───────────────────────┐
     │                       │  ─ 360° GOVERNANCE ─  │
     │  The AI Airspace      │                       │
     │  Control System       │     [  RING + TEX  ]  │
     │                       │                       │
     │  Full-lifecycle...    │                       │
     │                       │                       │
     │  [ Book a demo  ]     │                       │
     │  [ See how it… ]      │                       │
     └───────────────────────┴───────────────────────┘

   Left column (.hs-copy):
     - Headline (italic Fraunces, left-aligned)
     - Descriptor
     - CTA stack (primary + ghost, stacked vertically)
   Right column (.hs-scene-col):
     - 360° GOVERNANCE eyebrow
     - Ring + Tex inside the ring

   At <980px the two columns collapse to vertical: eyebrow + ring
   first, then headline/descriptor/CTAs below.

   Props
   -----
   openTrial:   () => void   — opens the Calendly modal
   navigate:    (path) => void — pushes a client-side route
   ============================================================= */

export default function HeroSection({ openTrial, navigate }) {
  return (
    <section className="hero-section" id="top">
      <div className="hs-stage">
        {/* LEFT COLUMN — copy + CTAs */}
        <div className="hs-copy">
          <h1 className="hs-headline">
            The AI Airspace Control System
          </h1>

          <p className="hs-descriptor">
            Full-lifecycle governance for autonomous AI systems —
            <span className="hs-descriptor-em"> spanning discovery, identity, observability, execution control, cryptographic evidence, and continuous evolution.</span>
          </p>

          <div className="hs-cta-stack">
            <button
              type="button"
              onClick={openTrial}
              className="hs-cta-primary"
            >
              <span>Book a demo</span>
              <span className="hs-cta-arrow">→</span>
            </button>
            <a
              href="/how-it-works"
              className="hs-cta-ghost"
              onClick={(e) => {
                e.preventDefault();
                navigate('/how-it-works');
              }}
            >
              <span>See how it works</span>
              <span className="hs-cta-arrow">→</span>
            </a>
          </div>
        </div>

        {/* RIGHT COLUMN — eyebrow above, ring + Tex below */}
        <div className="hs-scene-col">
          <div className="hs-eyebrow" aria-hidden="false">
            <span className="hs-eyebrow-mark" />
            <span className="hs-eyebrow-text">360° Governance</span>
            <span className="hs-eyebrow-mark" />
          </div>

          <div className="hs-scene">
            <div className="hs-ring-anchor">
              <EcosystemRing />
            </div>

            <div className="hs-figure-stage">
              <div className="hs-floor-disk" aria-hidden="true" />
              <div className="hs-scanline" aria-hidden="true" />

              <div className="hs-figure-position">
                <div className="hs-figure-breathe">
                  <img
                    src={texAvatar}
                    alt="Tex — the AI airspace control system"
                    className="hs-figure-img"
                  />
                  <div className="hs-eye-glow" aria-hidden="true" />
                  <div className="hs-chest-glow" aria-hidden="true" />
                </div>

                <span className="hs-pulse-ring" aria-hidden="true" />
                <span className="hs-pulse-ring" aria-hidden="true" />
                <span className="hs-pulse-ring" aria-hidden="true" />
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Scroll cue */}
      <a href="#how-it-works" className="hs-scroll-cue" aria-label="Scroll to how it works">
        <span>Scroll</span>
        <span className="hs-scroll-arrow">↓</span>
      </a>
    </section>
  );
}
