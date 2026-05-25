import React, { useEffect, useRef } from 'react';
import './HeroSection.css';

/* =============================================================
   HERO SECTION — Tex

   A single, decisive statement:
     • A small wordmark: "Tex."
     • The avatar, emerging from the page, alive.
     • Nothing else.

   The avatar carries the moment. He breathes, blinks, his core
   pulses, his eyes hold a steady glow, and a soft scan of light
   periodically passes across him. He gently tracks the cursor.
   ============================================================= */

export default function HeroSection({ openTrial, navigate }) {
  const stageRef = useRef(null);
  const figureRef = useRef(null);

  // Cursor-aware parallax — Tex very subtly turns toward the visitor.
  useEffect(() => {
    const stage = stageRef.current;
    const figure = figureRef.current;
    if (!stage || !figure) return;

    if (window.matchMedia('(prefers-reduced-motion: reduce)').matches) return;

    let raf = 0;
    let tx = 0, ty = 0;   // target translation in px
    let cx = 0, cy = 0;   // current translation in px

    const onMove = (e) => {
      const rect = stage.getBoundingClientRect();
      const x = (e.clientX - rect.left) / rect.width  - 0.5;
      const y = (e.clientY - rect.top)  / rect.height - 0.5;
      // Clamp to [-1, 1], then scale: max ~7px horizontal, ~3.5px vertical
      tx = Math.max(-1, Math.min(1, x)) * 7;
      ty = Math.max(-1, Math.min(1, y)) * 3.5;
    };

    const tick = () => {
      cx += (tx - cx) * 0.06;
      cy += (ty - cy) * 0.06;
      figure.style.setProperty('--tex-px', `${cx.toFixed(2)}px`);
      figure.style.setProperty('--tex-py', `${cy.toFixed(2)}px`);
      raf = requestAnimationFrame(tick);
    };

    window.addEventListener('mousemove', onMove, { passive: true });
    raf = requestAnimationFrame(tick);

    return () => {
      window.removeEventListener('mousemove', onMove);
      cancelAnimationFrame(raf);
    };
  }, []);

  return (
    <section className="tex-hero" id="top">
      {/* TOP BAR ------------------------------------------------ */}
      <header className="tex-topbar">
        <a
          href="/"
          className="tex-brand"
          onClick={(e) => { e.preventDefault(); navigate('/'); }}
          aria-label="Tex — home"
        >
          <span className="tex-brand-mark">T</span>
          <span className="tex-brand-word">Tex</span>
        </a>

        <div className="tex-presence" role="status" aria-live="polite">
          <span className="tex-presence-dot">
            <span className="tex-presence-dot-core" />
          </span>
          <span className="tex-presence-label">Tex is here</span>
        </div>

        <nav className="tex-nav">
          <a href="/how-it-works" className="tex-nav-link"
             onClick={(e) => { e.preventDefault(); navigate('/how-it-works'); }}>
            How it works
          </a>
          <a href="/evidence" className="tex-nav-link"
             onClick={(e) => { e.preventDefault(); navigate('/evidence'); }}>
            Evidence
          </a>
          <a href="/company" className="tex-nav-link"
             onClick={(e) => { e.preventDefault(); navigate('/company'); }}>
            Company
          </a>
          <a href="/sign-in" className="tex-nav-link tex-nav-link--strong"
             onClick={(e) => { e.preventDefault(); navigate('/sign-in'); }}>
            Sign in
          </a>
        </nav>
      </header>

      {/* STAGE -------------------------------------------------- */}
      <div className="tex-stage" ref={stageRef}>
        <div className="tex-atmosphere" aria-hidden="true" />

        <div className="tex-figure-column">
          <h1 className="tex-hero-name tex-arrive tex-arrive--name">Tex.</h1>

          <figure
            ref={figureRef}
            className="tex-figure tex-arrive tex-arrive--figure"
          >
            {/* Back atmospheric glow */}
            <div className="tex-figure-halo" aria-hidden="true" />

            {/* Breath layer — gentle vertical rise/fall */}
            <div className="tex-figure-breath">
              {/* Parallax layer — cursor-driven translation */}
              <div className="tex-figure-track">
                <picture>
                  <source media="(min-width: 720px)" srcSet="/tex-avatar.webp" />
                  <img
                    src="/tex-avatar-sm.webp"
                    alt="Tex"
                    className="tex-figure-img"
                    draggable="false"
                  />
                </picture>

                {/* Eye glow overlays — sit precisely over the avatar's
                    printed eye slits, brightening them */}
                <span className="tex-eye tex-eye--l" aria-hidden="true" />
                <span className="tex-eye tex-eye--r" aria-hidden="true" />

                {/* Blink shutters — periodically dim the eyes */}
                <span className="tex-blink tex-blink--l" aria-hidden="true" />
                <span className="tex-blink tex-blink--r" aria-hidden="true" />

                {/* Forehead emblem glow — softer pulse, in sync with breath */}
                <span className="tex-crown" aria-hidden="true" />

                {/* Chest core — heartbeat rhythm */}
                <span className="tex-core" aria-hidden="true" />

                {/* Scan sheet — periodic processing pass */}
                <span className="tex-scan" aria-hidden="true" />
              </div>
            </div>

            {/* Floor / contact glow — beneath the dissolve, anchors
                him to the surface he's emerging through */}
            <div className="tex-floor" aria-hidden="true" />
          </figure>
        </div>
      </div>
    </section>
  );
}
