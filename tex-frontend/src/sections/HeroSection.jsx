import React from 'react';
import './HeroSection.css';

/* =============================================================
   HERO SECTION — Quiet
   ────────────────────────────────────────────────────────────
   The whole homepage hero in one sentence:

       Quiet.

       Every agent. Every action. Every stage of its life.
       Tex is the only system that governs all of it.

       [ Show me ]

   Top bar:  T mark + "Tex"        •Tex is here        nav        Sign in
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

        <div className="tex-presence" role="status" aria-live="polite">
          <span className="tex-presence-dot" />
          <span className="tex-presence-label">Tex is here</span>
        </div>

        <nav className="tex-nav">
          <a
            href="/how-it-works"
            className="tex-nav-link"
            onClick={(e) => {
              e.preventDefault();
              navigate('/how-it-works');
            }}
          >
            How it works
          </a>
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
            href="/company"
            className="tex-nav-link"
            onClick={(e) => {
              e.preventDefault();
              navigate('/company');
            }}
          >
            Company
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
        <h1 className="tex-hero-word">Quiet.</h1>

        <p className="tex-hero-line">
          Every agent. Every action. Every stage of its life.
        </p>
        <p className="tex-hero-aside">
          Tex is the only system that governs all of it.
        </p>

        <div className="tex-hero-actions">
          <button
            type="button"
            className="tex-btn tex-btn--primary"
            onClick={openTrial}
          >
            Show me
          </button>
        </div>
      </div>

      {/* QUIET SCROLL CUE -------------------------------------- */}
      <a
        href="#moment"
        className="tex-scroll-cue"
        aria-label="Continue"
      >
        <span className="tex-scroll-arrow">↓</span>
      </a>
    </section>
  );
}
