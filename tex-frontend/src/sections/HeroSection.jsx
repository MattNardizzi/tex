import React from 'react';
import texAvatar from '../tex-avatar.png';
import EcosystemRing from './EcosystemRing.jsx';
import './HeroSection.css';

/* =============================================================
   HERO SECTION — the first thing visitors see.

   Vertical flow (top to bottom):
     1. Tex wordmark            — large italic serif, above the figure
     2. Ecosystem ring          — six layers arching above Tex's head
     3. Tex avatar              — centered, breathing motion
     4. Headline + descriptor   — italic gradient + lifecycle copy
     5. CTAs                    — Book a demo + See how it works
     6. Scroll cue

   The duplicate brand strip (TEX | VORTEXBLACK | AIRSPACE CONTROL
   SYSTEM) was removed in this revision because it said the same
   thing as the wordmark + headline below. The top-level navigation
   bar (rendered by App.jsx → LayerBar) carries the brand mark on
   the left and is enough.

   Props
   -----
   openTrial:   () => void   — opens the Calendly modal
   navigate:    (path) => void — pushes a client-side route
   ============================================================= */

export default function HeroSection({ openTrial, navigate }) {
  return (
    <section className="hero-section" id="top">
      {/* The stage — vertical flow:
            ring → wordmark → figure-row → content */}
      <div className="hs-stage">
        {/* The six-layer ecosystem ring — sequential light-up.
            Sits at the very top of the stage. Spans the full viewport
            width regardless of the stage's max-width container. */}
        <div className="hs-ring-anchor">
          <EcosystemRing />
        </div>

        {/* The "Tex" wordmark sits BETWEEN the ring and Tex's head,
            as a brand stamp directly above the figure. Italic serif,
            large. Its negative top margin pulls it up to overlap
            the ring's lower portion, knitting the two together. */}
        <div className="hs-wordmark" aria-hidden="true">Tex</div>

        {/* Figure row — CTAs flank Tex horizontally.
            Layout: [Book a demo]   [TEX FIGURE]   [See how it works]
            Each CTA sits at Tex's chest height, evenly spaced from
            the figure. The figure itself keeps its breathing motion,
            chest glow, eye glow, scan line, floor disk, and pulse
            rings — none of those are affected by the new grid. */}
        <div className="hs-figure-row">
          {/* LEFT CTA — primary (Book a demo → Calendly modal) */}
          <div className="hs-figure-cta hs-figure-cta--left">
            <button
              type="button"
              onClick={openTrial}
              className="hs-cta-primary"
            >
              <span>Book a demo</span>
              <span className="hs-cta-arrow">→</span>
            </button>
          </div>

          {/* CENTER — the figure itself, unchanged */}
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

          {/* RIGHT CTA — ghost (See how it works → /how-it-works route) */}
          <div className="hs-figure-cta hs-figure-cta--right">
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

        {/* Copy block below the figure row.
            The CTAs used to live here; they were promoted to flank
            Tex above. What remains is headline + descriptor only. */}
        <div className="hs-content">
          <h1 className="hs-headline">
            The AI Airspace Control System
          </h1>

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
