import React from 'react';
import texAvatar from '../tex-avatar.png';
import EcosystemRing from './EcosystemRing.jsx';
import './HeroSection.css';

/* =============================================================
   HERO SECTION — the first thing visitors see.

   Composition (top to bottom):
   1. Top kicker:   TEX · VORTEXBLACK · ECOSYSTEM AUTHORITY
   2. Ecosystem ring:    arches above Tex with six layers labeled
   3. Tex avatar:        centered, animated breathing + scan line
   4. Headline + subhead + CTAs: pinned to the lower-center column
   5. Scroll cue:        bottom-center

   The hero owns its own layout; the navigation bar is rendered
   by App.jsx (LayerBar). Calendly is also owned by App.jsx
   (TrialModal + TrialContext). This file only needs to call
   `openTrial()` for the primary CTA and `navigate('/how-it-works')`
   for the secondary CTA.

   Props
   -----
   openTrial:   () => void   — opens the Calendly modal
   navigate:    (path) => void — pushes a client-side route
   ============================================================= */

export default function HeroSection({ openTrial, navigate }) {
  return (
    <section className="hero-section" id="top">
      {/* Top kicker — preserves the same authority strip as before.
          On mobile the trailing "AIRSPACE CONTROL SYSTEM" segment is
          hidden (the headline below already says it) to prevent wrap. */}
      <div className="hs-kicker" aria-hidden="false">
        <span className="hs-kicker-dot" />
        <span className="hs-kicker-tex">TEX</span>
        <span className="hs-kicker-sep" />
        <span className="hs-kicker-dim">VORTEXBLACK</span>
        <span className="hs-kicker-sep hs-kicker-sep--collapse" />
        <span className="hs-kicker-dim hs-kicker-dim--collapse">AIRSPACE CONTROL SYSTEM</span>
      </div>

      {/* The stage — Tex centered, ring above, copy below */}
      <div className="hs-stage">
        {/* The six-layer ecosystem ring — sequential light-up */}
        <div className="hs-ring-anchor">
          <EcosystemRing />
        </div>

        {/* Tex figure — centered. Subtle breathing motion + chest
            and eye glow + scan line. The ring sits behind the head;
            Tex sits in front so the chest emblem reads cleanly. */}
        <div className="hs-figure-stage">
          <div className="hs-figure-veil" aria-hidden="true" />
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

          {/* Pulse rings emanating from chest emblem */}
          <span className="hs-pulse-ring" aria-hidden="true" />
          <span className="hs-pulse-ring" aria-hidden="true" />
          <span className="hs-pulse-ring" aria-hidden="true" />
        </div>

        {/* Copy + CTAs — sits below Tex.
            Composition:
              Tex          — wordmark (large serif)
              The AI Airspace Control System  — italic headline
              Full-lifecycle governance...    — descriptor sentence
              [Book a demo]  [See how it works] */}
        <div className="hs-content">
          <div className="hs-wordmark" aria-hidden="true">Tex</div>

          <h1 className="hs-headline">
            The AI Airspace Control System
          </h1>

          <p className="hs-descriptor">
            Full-lifecycle governance for autonomous AI systems —
            <span className="hs-descriptor-em"> spanning discovery, identity, observability, execution control, cryptographic evidence, and continuous evolution.</span>
          </p>

          <div className="hs-actions">
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
