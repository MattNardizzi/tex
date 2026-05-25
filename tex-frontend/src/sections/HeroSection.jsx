import React from 'react';
import './HeroSection.css';

/* =============================================================
   HERO SECTION — Tex
   ────────────────────────────────────────────────────────────
   The whole homepage hero in one frame:

       [ Tex, standing, breathing, watching ]

       Tex.

       Every agent. Every action. Every stage of its life.

       [ Show me ]

   No tagline above the figure. No explanation. The avatar IS
   the product. The page introduces him by showing him.
   ============================================================= */

export default function HeroSection({ openTrial, navigate }) {
  return (
    <section className="tex-hero" id="top">
      {/* TOP BAR ------------------------------------------------ */}
      <header className="tex-topbar">
        <a
          href="/"
          className="tex-brand"
          onClick={(e) => {
            e.preventDefault();
            navigate('/');
          }}
          aria-label="Tex — home"
        >
          <span className="tex-brand-mark">T</span>
          <span className="tex-brand-word">Tex</span>
        </a>

        <nav className="tex-nav">
          <a
            href="/evidence"
            className="tex-nav-link"
            onClick={(e) => {
              e.preventDefault();
              navigate('/evidence');
            }}
          >
            Evidence
          </a>
          <a
            href="/sign-in"
            className="tex-nav-link tex-nav-link--strong"
            onClick={(e) => {
              e.preventDefault();
              navigate('/sign-in');
            }}
          >
            Sign in
          </a>
        </nav>
      </header>

      {/* STAGE -------------------------------------------------- */}
      <div className="tex-stage">
        {/* The avatar — the product introduces itself by being itself. */}
        <figure className="tex-figure tex-arrive tex-arrive--figure">
          <div className="tex-figure-halo" aria-hidden="true" />
          <picture>
            <source
              media="(min-width: 720px)"
              srcSet="/tex-avatar.webp"
            />
            <img
              src="/tex-avatar-sm.webp"
              alt="Tex"
              className="tex-figure-img"
              draggable="false"
            />
          </picture>
          {/* Eye glow overlays — pulse with the breath. */}
          <span className="tex-eye tex-eye--l" aria-hidden="true" />
          <span className="tex-eye tex-eye--r" aria-hidden="true" />
        </figure>

        <h1 className="tex-hero-name tex-arrive tex-arrive--name">Tex.</h1>

        <p className="tex-hero-line tex-arrive tex-arrive--line">
          <span className="tex-beat tex-beat--1">Every agent.</span>{' '}
          <span className="tex-beat tex-beat--2">Every action.</span>{' '}
          <span className="tex-beat tex-beat--3">Every stage of its life.</span>
        </p>

        <div className="tex-hero-actions tex-arrive tex-arrive--button">
          <button
            type="button"
            className="tex-btn tex-btn--primary"
            onClick={openTrial}
          >
            Show me
          </button>
        </div>
      </div>
    </section>
  );
}
