import React from 'react';
import texAvatar from '../tex-avatar.png';
import EcosystemRing from './EcosystemRing.jsx';
import './HeroSection.css';

/* =============================================================
   HERO SECTION

   Composition (top → bottom)
   --------------------------
     [ scene ]            — Tex stands centered inside the 360°
                            governance ring. The ring encircles
                            him; the six layers are distributed
                            around its circumference with Execution
                            Governance anchored at 6 o'clock.
     [ eyebrow ]          — "360° GOVERNANCE", mono caps, kicker
                            that translates the ring into a claim
                            before the headline reads
     [ headline ]         — "The AI Airspace Control System"
     [ descriptor ]       — full-lifecycle copy
     [ CTA row ]          — Book a demo  •  See how it works

   The old flanking-CTA layout was replaced because the ring needs
   the horizontal real estate, and centering the CTAs under the
   composition gives the whole hero a single vertical spine:
     ring perimeter → Tex → Execution anchor (bottom of ring)
                          → eyebrow → headline → CTAs.

   The "Tex" italic wordmark was removed — Tex's chest emblem
   already brands the figure, and the wordmark was colliding with
   the avatar's head.

   Props
   -----
   openTrial:   () => void   — opens the Calendly modal
   navigate:    (path) => void — pushes a client-side route
   ============================================================= */

export default function HeroSection({ openTrial, navigate }) {
  return (
    <section className="hero-section" id="top">
      <div className="hs-stage">
        {/* SCENE — ring + figure as one composed unit.
            The ring is absolutely positioned over the figure stage
            so it encircles Tex rather than sitting above him. */}
        <div className="hs-scene">
          {/* The 360° ring. Sits behind the figure but in front of
              the page backdrop. */}
          <div className="hs-ring-anchor">
            <EcosystemRing />
          </div>

          {/* The figure — preserved with all its existing effects
              (breathing, scanline, eye/chest glow, floor disk,
              pulse rings). The veil (the green "bubble" behind
              Tex) has been removed; the ring's own luminance does
              that job now, more deliberately. */}
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

            {/* Pulse rings emanating from chest emblem — kept,
                they reinforce the hub-and-spoke reading. */}
            <span className="hs-pulse-ring" aria-hidden="true" />
            <span className="hs-pulse-ring" aria-hidden="true" />
            <span className="hs-pulse-ring" aria-hidden="true" />
          </div>
        </div>

        {/* Copy block — eyebrow, headline, descriptor, CTAs */}
        <div className="hs-content">
          <div className="hs-eyebrow" aria-hidden="false">
            <span className="hs-eyebrow-mark" />
            <span className="hs-eyebrow-text">360° Governance</span>
            <span className="hs-eyebrow-mark" />
          </div>

          <h1 className="hs-headline">
            The AI Airspace Control System
          </h1>

          <p className="hs-descriptor">
            Full-lifecycle governance for autonomous AI systems —
            <span className="hs-descriptor-em"> spanning discovery, identity, observability, execution control, cryptographic evidence, and continuous evolution.</span>
          </p>

          <div className="hs-cta-row">
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
      </div>

      {/* Scroll cue */}
      <a href="#how-it-works" className="hs-scroll-cue" aria-label="Scroll to how it works">
        <span>Scroll</span>
        <span className="hs-scroll-arrow">↓</span>
      </a>
    </section>
  );
}
