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
          <span className="tex-presence-dot">
            <span className="tex-presence-dot-core" />
          </span>
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
        <h1 className="tex-hero-word tex-arrive tex-arrive--word" aria-label="Absolute.">
          <svg
            className="tex-hero-glass"
            viewBox="0 0 900 240"
            preserveAspectRatio="xMidYMid meet"
            aria-hidden="true"
          >
            <defs>
              <linearGradient id="tex-glass-body" x1="0%" y1="0%" x2="0%" y2="100%">
                <stop offset="0%"   stopColor="#F4F6FA" stopOpacity="0.98" />
                <stop offset="28%"  stopColor="#C8D2DE" stopOpacity="0.92" />
                <stop offset="58%"  stopColor="#5B6E84" stopOpacity="0.95" />
                <stop offset="100%" stopColor="#1D2733" stopOpacity="1"    />
              </linearGradient>

              <linearGradient id="tex-glass-rim" x1="0%" y1="0%" x2="0%" y2="100%">
                <stop offset="0%"  stopColor="#FFFFFF" stopOpacity="0.85" />
                <stop offset="14%" stopColor="#FFFFFF" stopOpacity="0"    />
                <stop offset="100%" stopColor="#FFFFFF" stopOpacity="0"   />
              </linearGradient>

              <radialGradient id="tex-word-floor" cx="50%" cy="50%" r="50%">
                <stop offset="0%"   stopColor="#0E1620" stopOpacity="0.10" />
                <stop offset="60%"  stopColor="#0E1620" stopOpacity="0.04" />
                <stop offset="100%" stopColor="#0E1620" stopOpacity="0"    />
              </radialGradient>

              <mask id="tex-glass-mask">
                <text
                  x="450" y="178"
                  textAnchor="middle"
                  fontFamily="var(--tex-serif)"
                  fontSize="186"
                  fontWeight="400"
                  letterSpacing="-11"
                  fill="#FFFFFF"
                >Absolute.</text>
              </mask>
            </defs>

            <ellipse cx="450" cy="210" rx="320" ry="14" fill="url(#tex-word-floor)" />

            <text
              x="450" y="178"
              textAnchor="middle"
              fontFamily="var(--tex-serif)"
              fontSize="186"
              fontWeight="400"
              letterSpacing="-11"
              fill="url(#tex-glass-body)"
            >Absolute.</text>

            <text
              x="450" y="178"
              textAnchor="middle"
              fontFamily="var(--tex-serif)"
              fontSize="186"
              fontWeight="400"
              letterSpacing="-11"
              fill="url(#tex-glass-rim)"
            >Absolute.</text>

            <text
              x="450" y="178"
              textAnchor="middle"
              fontFamily="var(--tex-serif)"
              fontSize="186"
              fontWeight="400"
              letterSpacing="-11"
              fill="none"
              stroke="#5B6E84"
              strokeOpacity="0.35"
              strokeWidth="0.6"
            >Absolute.</text>

            <g mask="url(#tex-glass-mask)">
              <rect
                className="tex-glass-sweep-rect"
                x="-200" y="0"
                width="280" height="240"
                fill="#E6F0FF"
                opacity="0.85"
              />
            </g>
          </svg>
        </h1>

        <p className="tex-hero-line">
          <span className="tex-beat tex-beat--1">Every agent.</span>{' '}
          <span className="tex-beat tex-beat--2">Every action.</span>{' '}
          <span className="tex-beat tex-beat--3">Every stage of its life.</span>
        </p>
        <p className="tex-hero-aside tex-arrive tex-arrive--aside">
          Tex is the only system that governs all of it.
        </p>

        <div className="tex-hero-actions tex-arrive tex-arrive--button">
          <button
            type="button"
            className="tex-btn tex-btn--glass"
            onClick={openTrial}
          >
            <span className="tex-btn-orbit" aria-hidden="true" />
            <span className="tex-btn-label">Show me</span>
          </button>
        </div>
      </div>

      {/* QUIET SCROLL CUE -------------------------------------- */}
      <a
        href="#moment"
        className="tex-scroll-cue tex-arrive tex-arrive--cue"
        aria-label="Continue"
      >
        <span className="tex-scroll-arrow">↓</span>
      </a>
    </section>
  );
}
