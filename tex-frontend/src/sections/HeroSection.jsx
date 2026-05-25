import React from 'react';
import texAvatar from '../tex-avatar.png';
import EcosystemRing from './EcosystemRing.jsx';
import './HeroSection.css';

/* =============================================================
   HERO SECTION

   Composition
   -----------
     [ scene row ]
        [  CTA-left  ]   [  TEX inside RING  ]   [  CTA-right  ]
     [ content ]
        [ 360° GOVERNANCE eyebrow ]
        [ The AI Airspace Control System ]
        [ descriptor ]

   The ring + Tex sit in the center column of a 3-column grid;
   the CTAs flank the ring at left and right so they can't push
   below the fold. Below the scene row, the eyebrow → headline →
   descriptor form the vertical spine that the ring's bottom
   anchor (Execution Governance at 6 o'clock) terminates into.

   The "Tex" italic wordmark was removed — the chest emblem brands
   the figure, and the wordmark was colliding with the avatar's
   head. The 360° eyebrow does the brand-stamp job better.

   Props
   -----
   openTrial:   () => void   — opens the Calendly modal
   navigate:    (path) => void — pushes a client-side route
   ============================================================= */

export default function HeroSection({ openTrial, navigate }) {
  return (
    <section className="hero-section" id="top">
      <div className="hs-stage">
        {/* TOP COPY — eyebrow + headline, sitting above Tex */}
        <div className="hs-top-copy">
          <div className="hs-eyebrow" aria-hidden="false">
            <span className="hs-eyebrow-mark" />
            <span className="hs-eyebrow-text">360° Governance</span>
            <span className="hs-eyebrow-mark" />
          </div>

          <h1 className="hs-headline">
            The AI Airspace Control System
          </h1>
        </div>

        {/* SCENE ROW — three columns: left CTA, ring+figure, right CTA */}
        <div className="hs-scene-row">
          {/* LEFT CTA — primary (Book a demo) */}
          <div className="hs-flank hs-flank--left">
            <button
              type="button"
              onClick={openTrial}
              className="hs-cta-primary"
            >
              <span>Book a demo</span>
              <span className="hs-cta-arrow">→</span>
            </button>
          </div>

          {/* CENTER — ring encircles Tex */}
          <div className="hs-scene">
            <div className="hs-ring-anchor">
              <EcosystemRing />
            </div>

            <div className="hs-figure-stage">
              <div className="hs-floor-disk" aria-hidden="true" />
              <div className="hs-scanline" aria-hidden="true" />

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

          {/* RIGHT CTA — ghost (See how it works) */}
          <div className="hs-flank hs-flank--right">
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

        {/* BOTTOM COPY — descriptor below Tex */}
        <div className="hs-bottom-copy">
          <p className="hs-descriptor">
            Full-lifecycle governance for autonomous AI systems —
            <span className="hs-descriptor-em"> spanning discovery, identity, observability, execution control, cryptographic evidence, and continuous evolution.</span>
          </p>
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
