import React, { useEffect, useMemo, useRef, useState } from 'react';
import texHero from './tex-hero.png';

/* ────────────────────────────────────────────────────────────────────
 * The Sevenfold — texaegis.com homepage hero (v4).
 *
 * The 5-second contract: a stranger lands, watches for five seconds,
 * and can complete the sentence "Tex is the thing that ____."
 *
 * To answer that, the hero shows ONE verdict happening end-to-end in
 * one frame:
 *
 *   - Left column: headline + LIVE TRANSCRIPT that types in sync with
 *     the bridge's actual evaluation phases. Each line lights one of
 *     the seven nodes on the ring. The transcript IS the explainer —
 *     by the time the buyer has watched one cycle they have seen the
 *     seven layers fire, fuse, and seal.
 *
 *   - Right column: Tex three-quarter, ring as a VOLUME (multi-stroke
 *     glow + particles riding the path), seven hexagonal nodes at
 *     fixed angles. Eyes change color with verdict. He breathes.
 *
 *   - On chain seal: a hash particle physically arcs from the left
 *     edge into Tex's chest emblem. The "cryptographically-linked"
 *     claim, performed.
 *
 * No new dependencies. Honors prefers-reduced-motion. All driven by
 * the existing Bridge — no fake animation; the timeline matches what
 * the real evaluation pipeline does.
 * ──────────────────────────────────────────────────────────────────── */

/* ─── The seven layers ─────────────────────────────────────────────── */

const LAYERS = [
  { n: '①', key: 'discovery',    name: 'Discovery',    stream: 'identity',      copy: 'identity'      },
  { n: '②', key: 'registration', name: 'Registration', stream: 'capability',    copy: 'capability'    },
  { n: '③', key: 'capability',   name: 'Capability',   stream: 'behavioral',    copy: 'behavioral'    },
  { n: '④', key: 'evaluation',   name: 'Evaluation',   stream: 'deterministic', copy: 'deterministic' },
  { n: '⑤', key: 'enforcement',  name: 'Enforcement',  stream: 'retrieval',     copy: 'retrieval'     },
  { n: '⑥', key: 'evidence',     name: 'Evidence',     stream: 'specialist',    copy: 'specialists'   },
  { n: '⑦', key: 'learning',     name: 'Learning',     stream: 'semantic',      copy: 'semantic'      },
];

/* ─── Geometry ─────────────────────────────────────────────────────── */

const VIEW_W = 1000;
const VIEW_H = 1000;
const CX = VIEW_W / 2;
const CY = 540;

const RING_RX = 360;
const RING_RY = 96;

const TEX_W = 460;
const TEX_H = 580;
const TEX_X = CX - TEX_W / 2;
const TEX_Y = CY - 320;

const NODES = LAYERS.map((layer, i) => {
  const theta = -Math.PI / 2 + (i * 2 * Math.PI) / 7;
  return {
    ...layer,
    i,
    theta,
    x: CX + RING_RX * Math.cos(theta),
    y: CY + RING_RY * Math.sin(theta),
    isFront: Math.sin(theta) > -0.1,
  };
});

/* ─── Reduced motion ──────────────────────────────────────────────── */

function useReducedMotion() {
  const [reduced, setReduced] = useState(false);
  useEffect(() => {
    if (typeof window === 'undefined') return;
    const mq = window.matchMedia('(prefers-reduced-motion: reduce)');
    setReduced(mq.matches);
    const handler = (e) => setReduced(e.matches);
    mq.addEventListener?.('change', handler);
    return () => mq.removeEventListener?.('change', handler);
  }, []);
  return reduced;
}

/* ─── Continuous clock for ambient motion ─────────────────────────── */

function useTick(reducedMotion) {
  const [tick, setTick] = useState(0);
  useEffect(() => {
    if (reducedMotion) { setTick(0); return; }
    const start = performance.now();
    let raf = 0;
    const step = (now) => {
      setTick(now - start);
      raf = requestAnimationFrame(step);
    };
    raf = requestAnimationFrame(step);
    return () => cancelAnimationFrame(raf);
  }, [reducedMotion]);
  return tick;
}

/* ─── Eye-track on pointer ────────────────────────────────────────── */

function useEyeTrack(stageRef, reducedMotion) {
  const [eye, setEye] = useState({ dx: 0, dy: 0 });
  useEffect(() => {
    if (reducedMotion || !stageRef.current) return;
    const el = stageRef.current;
    let raf = 0;
    let target = { dx: 0, dy: 0 };
    let current = { dx: 0, dy: 0 };
    const onMove = (e) => {
      const r = el.getBoundingClientRect();
      const cx = r.left + r.width / 2;
      const cy = r.top + r.height * 0.32;
      const dx = (e.clientX - cx) / (r.width / 2);
      const dy = (e.clientY - cy) / (r.height / 2);
      target = {
        dx: Math.max(-1, Math.min(1, dx)) * 4,
        dy: Math.max(-1, Math.min(1, dy)) * 2.5,
      };
    };
    const tick = () => {
      current.dx += (target.dx - current.dx) * 0.08;
      current.dy += (target.dy - current.dy) * 0.08;
      setEye({ dx: current.dx, dy: current.dy });
      raf = requestAnimationFrame(tick);
    };
    window.addEventListener('mousemove', onMove);
    raf = requestAnimationFrame(tick);
    return () => {
      window.removeEventListener('mousemove', onMove);
      cancelAnimationFrame(raf);
    };
  }, [stageRef, reducedMotion]);
  return eye;
}

/* ─── Component ───────────────────────────────────────────────────── */

export default function Sevenfold({
  verdict, phase, counters, chain,
  activeAction, activeStreams, activeFused, activeLayers,
}) {
  const reducedMotion = useReducedMotion();
  const tick = useTick(reducedMotion);
  const stageRef = useRef(null);
  const eye = useEyeTrack(stageRef, reducedMotion);

  const breathOffset = reducedMotion ? 0 : Math.sin(tick / 1900) * 2.4;
  const auraPulse = reducedMotion ? 0.7 : 0.62 + Math.sin(tick / 1900) * 0.08;

  const transcript = useTranscript({
    activeAction, activeStreams, activeFused, activeLayers, verdict, phase, chain,
  });

  const verdictKey = verdict || 'idle';
  const hashFlight = useHashFlight(chain, reducedMotion);

  const backNodes  = NODES.filter((n) => !n.isFront);
  const frontNodes = NODES.filter((n) =>  n.isFront);

  return (
    <section
      ref={stageRef}
      className={`sf sf-verdict-${verdictKey} sf-phase-${phase || 'idle'}`}
      aria-label="Tex — the adjudicator for every AI action"
    >
      <div className="sf-atmos" aria-hidden="true">
        <div className="sf-atmos-grid" />
        <div className="sf-atmos-glow" style={{ opacity: auraPulse }} />
        <div className="sf-atmos-fog" />
        <div className="sf-atmos-vignette" />
      </div>

      <div className="sf-frame">

        {/* ─────────── LEFT — narrative + transcript ─────────── */}
        <div className="sf-narrative">
          <div className="sf-eyebrow">
            <span className="sf-eyebrow-pip" aria-hidden="true" />
            <span>TEX&nbsp;·&nbsp;LIVE&nbsp;ADJUDICATION</span>
            <span className="sf-eyebrow-divider" />
            <span className="sf-eyebrow-spec">OWASP&nbsp;ASI&nbsp;2026</span>
          </div>

          <h1 className="sf-headline">
            The adjudicator for <em>every</em> AI action.
          </h1>

          <p className="sf-deck">
            Discovery, registration, capability, evaluation, enforcement,
            evidence, learning &mdash;{' '}
            <span className="sf-deck-em">one cryptographically-linked loop.</span>
            {' '}Not seven products stitched across vendors.
          </p>

          <Transcript
            transcript={transcript}
            verdict={verdictKey}
            phase={phase}
            reducedMotion={reducedMotion}
          />

          <div className="sf-cta-row">
            <a className="sf-cta sf-cta-primary" href="#evaluation">
              <span>Watch a live verdict</span>
              <span className="sf-cta-arrow" aria-hidden="true">↓</span>
            </a>
            <a className="sf-cta sf-cta-secondary" href="/asi">
              <span>Read the architecture</span>
              <span className="sf-cta-arrow" aria-hidden="true">→</span>
            </a>
          </div>
        </div>

        {/* ─────────── RIGHT — Tex + ring ─────────── */}
        <div className="sf-stage">
          <svg
            viewBox={`0 0 ${VIEW_W} ${VIEW_H}`}
            preserveAspectRatio="xMidYMid meet"
            className="sf-stage-svg"
            role="img"
            aria-label="Tex stands inside a cryptographic governance ring with seven layer nodes"
            xmlns="http://www.w3.org/2000/svg"
          >
            <defs>
              <linearGradient id="sf-ring-base" x1="0%" y1="0%" x2="100%" y2="0%">
                <stop offset="0%"   stopColor="#1d8fb8" stopOpacity="0.35" />
                <stop offset="50%"  stopColor="#9af0ff" stopOpacity="1"    />
                <stop offset="100%" stopColor="#1d8fb8" stopOpacity="0.35" />
              </linearGradient>
              <linearGradient id="sf-ring-chroma-cyan" x1="0%" y1="0%" x2="100%" y2="0%">
                <stop offset="0%"   stopColor="#5ee0ff" stopOpacity="0" />
                <stop offset="50%"  stopColor="#5ee0ff" stopOpacity="0.7" />
                <stop offset="100%" stopColor="#5ee0ff" stopOpacity="0" />
              </linearGradient>
              <linearGradient id="sf-ring-chroma-violet" x1="0%" y1="0%" x2="100%" y2="0%">
                <stop offset="0%"   stopColor="#b388ff" stopOpacity="0" />
                <stop offset="50%"  stopColor="#b388ff" stopOpacity="0.55" />
                <stop offset="100%" stopColor="#b388ff" stopOpacity="0" />
              </linearGradient>
              <radialGradient id="sf-aura" cx="50%" cy="50%" r="50%">
                <stop offset="0%"   stopColor="#5ee0ff" stopOpacity="0.34" />
                <stop offset="55%"  stopColor="#2fb8e0" stopOpacity="0.05" />
                <stop offset="100%" stopColor="#5ee0ff" stopOpacity="0"    />
              </radialGradient>
              <radialGradient id="sf-floor" cx="50%" cy="50%" r="50%">
                <stop offset="0%"   stopColor="#5ee0ff" stopOpacity="0.32" />
                <stop offset="50%"  stopColor="#5ee0ff" stopOpacity="0.06" />
                <stop offset="100%" stopColor="#5ee0ff" stopOpacity="0"    />
              </radialGradient>
              <radialGradient id="sf-pulse" cx="50%" cy="50%" r="50%">
                <stop offset="0%"   stopColor="#cef5ff" stopOpacity="1"   />
                <stop offset="35%"  stopColor="#5ee0ff" stopOpacity="0.7" />
                <stop offset="100%" stopColor="#5ee0ff" stopOpacity="0"   />
              </radialGradient>
              <radialGradient id="sf-node-fill" cx="50%" cy="50%" r="50%">
                <stop offset="0%"   stopColor="#0f1422" stopOpacity="0.95" />
                <stop offset="100%" stopColor="#04060c" stopOpacity="0.95" />
              </radialGradient>
              <filter id="sf-blur-lg" x="-50%" y="-50%" width="200%" height="200%">
                <feGaussianBlur stdDeviation="14" />
              </filter>
              <filter id="sf-blur-md" x="-50%" y="-50%" width="200%" height="200%">
                <feGaussianBlur stdDeviation="6" />
              </filter>
              <filter id="sf-blur-sm" x="-50%" y="-50%" width="200%" height="200%">
                <feGaussianBlur stdDeviation="2.2" />
              </filter>
            </defs>

            {/* Floor disc */}
            <ellipse cx={CX} cy={CY + 290} rx={300} ry={48}
                     fill="url(#sf-floor)" opacity="0.9" />

            {/* Ring back */}
            <RingArc half="back" tick={tick} />
            {!reducedMotion && <RingParticles tick={tick} half="back" />}
            {backNodes.map((node) => (
              <RingNode
                key={node.key}
                node={node}
                active={activeLayers > node.i}
                fired={activeLayers === node.i + 1}
                verdict={verdictKey}
                phase={phase}
              />
            ))}

            {/* Avatar */}
            <g transform={`translate(0, ${breathOffset})`}>
              <ellipse cx={CX} cy={CY - 80} rx={290} ry={360}
                       fill="url(#sf-aura)" opacity={auraPulse} />
              <image
                href={texHero}
                x={TEX_X}
                y={TEX_Y}
                width={TEX_W}
                height={TEX_H}
                preserveAspectRatio="xMidYMid meet"
                style={{ filter: 'drop-shadow(0 0 28px rgba(94,224,255,0.22))' }}
              />
              <EyeOverlay
                cx={CX}
                cy={TEX_Y + TEX_H * 0.31}
                eye={eye}
                verdict={verdictKey}
                phase={phase}
                reducedMotion={reducedMotion}
              />
              <ChestImpact
                cx={CX}
                cy={TEX_Y + TEX_H * 0.74}
                tick={tick}
                hashFlight={hashFlight}
                verdict={verdictKey}
              />
            </g>

            {/* Ring front */}
            <RingArc half="front" tick={tick} />
            {!reducedMotion && <RingParticles tick={tick} half="front" />}
            {frontNodes.map((node) => (
              <RingNode
                key={node.key}
                node={node}
                active={activeLayers > node.i}
                fired={activeLayers === node.i + 1}
                verdict={verdictKey}
                phase={phase}
              />
            ))}

            {/* Traveling pulse */}
            {!reducedMotion && <TravelingPulse tick={tick} />}

            {/* Hash flight (chain seal) */}
            {hashFlight && !reducedMotion && (
              <HashFlight hashFlight={hashFlight} chestY={TEX_Y + TEX_H * 0.74} />
            )}
          </svg>

          <VerdictCallout verdict={verdictKey} phase={phase} fused={activeFused} />
        </div>
      </div>
    </section>
  );
}

/* ─── The transcript ─────────────────────────────────────────────── */

function useTranscript({ activeAction, activeStreams, activeFused, activeLayers, verdict, phase, chain }) {
  return useMemo(() => {
    if (!activeAction) {
      return { lines: [], header: null, footer: null };
    }
    const ts = activeAction.ts || '00:00:00';
    const header = {
      ts,
      agent: activeAction.agent,
      verb: activeAction.verb,
      target: activeAction.target,
    };
    const lines = [];
    for (let i = 0; i < 7; i++) {
      if (activeLayers <= i) break;
      const layer = LAYERS[i];
      const score = activeStreams?.[layer.stream] ?? 0;
      const flag = scoreFlag(score, verdict);
      lines.push({ n: layer.n, name: layer.copy, score, flag });
    }
    let footer = null;
    if (phase === 'fused' || phase === 'verdict' || phase === 'idle') {
      footer = {
        fused: activeFused,
        verdict: verdict || 'pending',
        gate: gateFor(verdict),
        chainHash: chain && chain.length ? chain[chain.length - 1].hash : null,
        chainSealed: phase === 'verdict' || phase === 'idle',
      };
    }
    return { lines, header, footer };
  }, [activeAction, activeStreams, activeFused, activeLayers, verdict, phase, chain]);
}

function scoreFlag(score, verdict) {
  if (score >= 0.8) return verdict === 'permit' ? 'high-ok' : 'high-risk';
  if (score >= 0.55) return 'warn';
  return 'ok';
}

function gateFor(verdict) {
  if (verdict === 'forbid')  return { label: 'BLOCKED',  tone: 'forbid' };
  if (verdict === 'abstain') return { label: 'WITHHELD', tone: 'abstain' };
  if (verdict === 'permit')  return { label: 'RELEASED', tone: 'permit' };
  return null;
}

function Transcript({ transcript, verdict, phase, reducedMotion }) {
  const { header, lines, footer } = transcript;
  return (
    <div className={`sf-tx sf-tx-verdict-${verdict} sf-tx-phase-${phase || 'idle'}`}>
      <div className="sf-tx-frame">
        <div className="sf-tx-rule" aria-hidden="true">
          <span className="sf-tx-rule-mark" />
          <span className="sf-tx-rule-label">/  evaluation stream</span>
          <span className="sf-tx-rule-fill" />
          <span className="sf-tx-rule-status">
            <span className="sf-tx-rule-pip" /> live
          </span>
        </div>

        <div className="sf-tx-body">
          {header ? (
            <>
              <div className="sf-tx-row sf-tx-row-head">
                <span className="sf-tx-ts">{header.ts}</span>
                <span className="sf-tx-tag">action</span>
                <span className="sf-tx-val">
                  <span className="sf-tx-agent">{header.agent}</span>
                  <span className="sf-tx-arrow">·</span>
                  <span className="sf-tx-verb">{header.verb}</span>
                  <span className="sf-tx-arrow">→</span>
                  <span className="sf-tx-target">{header.target}</span>
                </span>
              </div>

              {lines.map((ln, i) => (
                <div className={`sf-tx-row sf-tx-row-layer sf-tx-flag-${ln.flag}`} key={i}>
                  <span className="sf-tx-ts">{header.ts}</span>
                  <span className="sf-tx-tag">layer</span>
                  <span className="sf-tx-n">{ln.n}</span>
                  <span className="sf-tx-name">{ln.name}</span>
                  <span className="sf-tx-bar" aria-hidden="true">
                    <span
                      className="sf-tx-bar-fill"
                      style={{ width: `${Math.round(ln.score * 100)}%` }}
                    />
                  </span>
                  <span className="sf-tx-score">{ln.score.toFixed(2)}</span>
                  <span className={`sf-tx-mark sf-tx-mark-${ln.flag}`}>
                    {flagMark(ln.flag)}
                  </span>
                </div>
              ))}

              {footer && footer.fused != null && footer.fused > 0 && (
                <div className="sf-tx-row sf-tx-row-fuse">
                  <span className="sf-tx-ts">{header.ts}</span>
                  <span className="sf-tx-tag">fuse</span>
                  <span className="sf-tx-name">weighted</span>
                  <span className="sf-tx-bar" aria-hidden="true">
                    <span
                      className="sf-tx-bar-fill sf-tx-bar-fused"
                      style={{ width: `${Math.round(footer.fused * 100)}%` }}
                    />
                  </span>
                  <span className="sf-tx-score">{footer.fused.toFixed(2)}</span>
                  <span className={`sf-tx-verdict sf-tx-verdict-${footer.verdict}`}>
                    → {(footer.verdict || '').toUpperCase()}
                  </span>
                </div>
              )}

              {footer && footer.chainHash && (
                <div className="sf-tx-row sf-tx-row-chain">
                  <span className="sf-tx-ts">{header.ts}</span>
                  <span className="sf-tx-tag">chain</span>
                  <span className="sf-tx-hash">{shortHash(footer.chainHash)}</span>
                  <span className="sf-tx-bar-spacer" />
                  <span className={`sf-tx-mark sf-tx-mark-${footer.chainSealed ? 'sealed' : 'pending'}`}>
                    {footer.chainSealed ? 'sealed' : 'sealing…'}
                  </span>
                </div>
              )}

              {footer && footer.gate && (
                <div className={`sf-tx-row sf-tx-row-gate sf-tx-gate-${footer.gate.tone}`}>
                  <span className="sf-tx-ts">{header.ts}</span>
                  <span className="sf-tx-tag">gate</span>
                  <span className="sf-tx-name">fail-closed</span>
                  <span className="sf-tx-bar-spacer" />
                  <span className={`sf-tx-gate-label sf-tx-gate-label-${footer.gate.tone}`}>
                    {footer.gate.label}
                  </span>
                </div>
              )}
            </>
          ) : (
            <div className="sf-tx-row sf-tx-row-idle">
              <span className="sf-tx-ts">--:--:--</span>
              <span className="sf-tx-tag">await</span>
              <span className="sf-tx-name sf-tx-dim">listening for next action…</span>
            </div>
          )}
        </div>

        <div className="sf-tx-foot" aria-hidden="true">
          <span className="sf-tx-foot-rule" />
          <span className="sf-tx-foot-label">end of stream &nbsp;·&nbsp; <em>~80&thinsp;ms</em></span>
        </div>
      </div>
    </div>
  );
}

function flagMark(flag) {
  switch (flag) {
    case 'high-ok':   return '✓';
    case 'ok':        return '✓';
    case 'warn':      return '⚠';
    case 'high-risk': return '✕';
    default:          return '·';
  }
}

function shortHash(h) {
  if (!h || h.length < 8) return '--------';
  return `${h.slice(0, 4)}..${h.slice(-4)}`;
}

/* ─── Verdict callout ──────────────────────────────────────────── */

function VerdictCallout({ verdict, phase, fused }) {
  const visible = phase === 'verdict' || phase === 'fused';
  const v = verdict === 'idle' ? 'pending' : verdict;
  return (
    <div className={`sf-callout sf-callout-${v} ${visible ? 'is-visible' : ''}`}>
      <span className="sf-callout-rule" />
      <span className="sf-callout-label">{(v || 'pending').toUpperCase()}</span>
      {fused != null && fused > 0 && (
        <span className="sf-callout-score">
          fused <strong>{fused.toFixed(2)}</strong>
        </span>
      )}
      <span className="sf-callout-rule" />
    </div>
  );
}

/* ─── Ring arc ────────────────────────────────────────────────── */

function ringPath(startTheta, endTheta) {
  const start = ringPoint(startTheta);
  const end = ringPoint(endTheta);
  const sweep = ((endTheta - startTheta) + 2 * Math.PI) % (2 * Math.PI);
  const largeArc = sweep > Math.PI ? 1 : 0;
  return `M${start.x.toFixed(2)},${start.y.toFixed(2)} A${RING_RX},${RING_RY} 0 ${largeArc} 1 ${end.x.toFixed(2)},${end.y.toFixed(2)}`;
}
function ringPoint(theta) {
  return { x: CX + RING_RX * Math.cos(theta), y: CY + RING_RY * Math.sin(theta) };
}

function RingArc({ half, tick }) {
  const a = Math.PI + 0.1;
  const b = 2 * Math.PI - 0.1;
  const offset = (tick / 14000) * 200;

  if (half === 'back') {
    const path = ringPath(a, b);
    return (
      <g className="sf-ring sf-ring-back">
        <path d={path} fill="none" stroke="#5ee0ff" strokeWidth="22"
              opacity="0.10" filter="url(#sf-blur-lg)" />
        <path d={path} fill="none" stroke="url(#sf-ring-base)" strokeWidth="2.6"
              opacity="0.55" filter="url(#sf-blur-sm)" />
        <g transform="translate(0, -0.7)">
          <path d={path} fill="none" stroke="url(#sf-ring-chroma-cyan)"
                strokeWidth="1.4" opacity="0.6" />
        </g>
        <g transform="translate(0, 0.7)">
          <path d={path} fill="none" stroke="url(#sf-ring-chroma-violet)"
                strokeWidth="1.4" opacity="0.45" />
        </g>
        <path d={path} fill="none" stroke="#cef5ff" strokeWidth="0.6"
              opacity="0.55" strokeDasharray="0.6 8" strokeDashoffset={-offset} />
      </g>
    );
  }

  const arc1 = ringPath(b, 2 * Math.PI - 0.0001);
  const arc2 = ringPath(0, a);
  return (
    <g className="sf-ring sf-ring-front">
      {[arc1, arc2].map((p, i) => (
        <g key={i}>
          <path d={p} fill="none" stroke="#5ee0ff" strokeWidth="28"
                opacity="0.13" filter="url(#sf-blur-lg)" />
          <path d={p} fill="none" stroke="url(#sf-ring-base)" strokeWidth="3"
                opacity="0.78" filter="url(#sf-blur-sm)" />
          <g transform="translate(0, -0.8)">
            <path d={p} fill="none" stroke="url(#sf-ring-chroma-cyan)"
                  strokeWidth="1.6" opacity="0.75" />
          </g>
          <g transform="translate(0, 0.8)">
            <path d={p} fill="none" stroke="url(#sf-ring-chroma-violet)"
                  strokeWidth="1.6" opacity="0.6" />
          </g>
          <path d={p} fill="none" stroke="#e7faff" strokeWidth="0.7"
                opacity="0.85" strokeDasharray="0.8 8" strokeDashoffset={-offset} />
        </g>
      ))}
    </g>
  );
}

/* ─── Particles ─────────────────────────────────────────────── */

const PARTICLE_COUNT = 24;
const PARTICLE_SEEDS = Array.from({ length: PARTICLE_COUNT }, (_, i) => ({
  phase: (i / PARTICLE_COUNT) + (Math.sin(i * 7.31) * 0.11),
  speed: 0.4 + ((i * 1.71) % 1) * 1.2,
  size:  0.8 + ((i * 2.13) % 1) * 1.6,
  alpha: 0.25 + ((i * 1.07) % 1) * 0.55,
}));

function RingParticles({ tick, half }) {
  const t = (tick / 9000);
  return (
    <g className={`sf-particles sf-particles-${half}`}>
      {PARTICLE_SEEDS.map((p, i) => {
        let theta = (-Math.PI / 2 + 2 * Math.PI * (p.phase + t * p.speed)) % (2 * Math.PI);
        if (theta < 0) theta += 2 * Math.PI;
        const isFront = Math.sin(theta) > -0.1;
        if (half === 'front' ? !isFront : isFront) return null;
        const pt = ringPoint(theta);
        const depthAlpha = (half === 'front' ? 1 : 0.45) * p.alpha;
        return (
          <circle
            key={i}
            cx={pt.x}
            cy={pt.y}
            r={p.size}
            fill="#cef5ff"
            opacity={depthAlpha}
            filter="url(#sf-blur-sm)"
          />
        );
      })}
    </g>
  );
}

/* ─── Traveling pulse ───────────────────────────────────────── */

function TravelingPulse({ tick }) {
  const cycleMs = 7000;
  const t = (tick % cycleMs) / cycleMs;
  const theta = -Math.PI / 2 + t * 2 * Math.PI;
  const p = ringPoint(theta);
  return (
    <g className="sf-pulse">
      <circle cx={p.x} cy={p.y} r="22" fill="url(#sf-pulse)" opacity="0.85" />
      <circle cx={p.x} cy={p.y} r="6"  fill="#cef5ff" opacity="0.95" />
      <circle cx={p.x} cy={p.y} r="2.4" fill="#ffffff" />
    </g>
  );
}

/* ─── Ring node ──────────────────────────────────────────── */

function RingNode({ node, active, fired, verdict, phase }) {
  const size = 17;
  const hex = hexagon(node.x, node.y, size);
  const lit = active || fired;
  const verdictTone =
    fired && phase === 'verdict' ? verdict
    : 'idle';
  return (
    <g className={`sf-node sf-node-${node.key} ${lit ? 'is-lit' : ''} ${fired ? 'is-fired' : ''} sf-node-tone-${verdictTone}`}>
      {fired && (
        <polygon
          points={hexagon(node.x, node.y, size + 10)}
          fill="#5ee0ff"
          opacity="0.3"
          filter="url(#sf-blur-md)"
        />
      )}
      <polygon
        points={hex}
        fill="url(#sf-node-fill)"
        stroke={lit ? '#9af0ff' : '#1f3a4d'}
        strokeWidth={lit ? 1.5 : 1}
      />
      <text x={node.x} y={node.y + 4} textAnchor="middle" className={`sf-node-label ${lit ? 'is-lit' : ''}`}>
        {node.n}
      </text>
      <text x={node.x} y={node.y + size + 18} textAnchor="middle" className="sf-node-name">
        {node.name.toUpperCase()}
      </text>
    </g>
  );
}

function hexagon(cx, cy, r) {
  const points = [];
  for (let i = 0; i < 6; i++) {
    const a = (Math.PI / 3) * i + Math.PI / 6;
    points.push(`${(cx + r * Math.cos(a)).toFixed(2)},${(cy + r * Math.sin(a)).toFixed(2)}`);
  }
  return points.join(' ');
}

/* ─── Eye overlay ──────────────────────────────────────── */

function EyeOverlay({ cx, cy, eye, verdict, phase, reducedMotion }) {
  const color =
    verdict === 'permit'  ? '#6fdca5' :
    verdict === 'abstain' ? '#ffb547' :
    verdict === 'forbid'  ? '#ff5b5b' :
                            '#5ee0ff';
  const flash = phase === 'verdict' && verdict !== 'idle';
  const ex = reducedMotion ? 0 : eye.dx;
  const ey = reducedMotion ? 0 : eye.dy;
  return (
    <g className={`sf-eyeoverlay ${flash ? 'is-flash' : ''}`} pointerEvents="none">
      <ellipse cx={cx - 26 + ex} cy={cy + ey} rx="14" ry="3.4" fill={color}
               opacity={flash ? 0.85 : 0.42} filter="url(#sf-blur-sm)" />
      <ellipse cx={cx + 26 + ex} cy={cy + ey} rx="14" ry="3.4" fill={color}
               opacity={flash ? 0.85 : 0.42} filter="url(#sf-blur-sm)" />
      <ellipse cx={cx - 26 + ex * 1.4} cy={cy + ey * 1.4} rx="3.4" ry="1.6" fill="#ffffff"
               opacity={flash ? 0.95 : 0.6} />
      <ellipse cx={cx + 26 + ex * 1.4} cy={cy + ey * 1.4} rx="3.4" ry="1.6" fill="#ffffff"
               opacity={flash ? 0.95 : 0.6} />
    </g>
  );
}

/* ─── Chest impact ─────────────────────────────────────── */

function ChestImpact({ cx, cy, tick, hashFlight, verdict }) {
  const breathing = (Math.sin(tick / 1900) * 0.5 + 0.5) * 0.4 + 0.4;
  const impactT = hashFlight ? hashFlight.impactT : 0;
  const ringR = 14 + impactT * 28;
  const ringA = (1 - impactT) * 0.9;
  const color =
    verdict === 'permit'  ? '#6fdca5' :
    verdict === 'abstain' ? '#ffb547' :
    verdict === 'forbid'  ? '#ff5b5b' :
                            '#5ee0ff';
  return (
    <g pointerEvents="none">
      <circle cx={cx} cy={cy} r="9" fill={color} opacity={breathing * 0.45} filter="url(#sf-blur-sm)" />
      {impactT > 0 && (
        <circle cx={cx} cy={cy} r={ringR} fill="none" stroke={color} strokeWidth="1.6" opacity={ringA} />
      )}
    </g>
  );
}

/* ─── Hash flight ───────────────────────────────────── */

function useHashFlight(chain, reducedMotion) {
  const [flight, setFlight] = useState(null);
  const lastLenRef = useRef(0);
  const tickRef = useRef(null);

  useEffect(() => {
    if (reducedMotion) return;
    if (!chain || chain.length === 0) return;
    if (chain.length === lastLenRef.current) return;
    lastLenRef.current = chain.length;
    const lastBlock = chain[chain.length - 1];
    if (!lastBlock) return;

    const start = performance.now();
    const duration = 900;
    setFlight({ startedAt: start, duration, t: 0, impactT: 0, hash: lastBlock.hash, verdict: lastBlock.verdict });

    const step = () => {
      const elapsed = performance.now() - start;
      const t = Math.min(1, elapsed / duration);
      const impactT = Math.max(0, (elapsed - duration * 0.85) / (duration * 0.4));
      setFlight((cur) => cur ? { ...cur, t, impactT: Math.min(1, impactT) } : cur);
      if (elapsed < duration + 360) {
        tickRef.current = requestAnimationFrame(step);
      } else {
        setFlight(null);
      }
    };
    tickRef.current = requestAnimationFrame(step);
    return () => { if (tickRef.current) cancelAnimationFrame(tickRef.current); };
  }, [chain, reducedMotion]);

  return flight;
}

function HashFlight({ hashFlight, chestY }) {
  const t = hashFlight.t;
  const sx = -40, sy = chestY + 60;
  const ex = CX, ey = chestY;
  const cxc = CX * 0.42, cyc = chestY - 220;
  const x = (1 - t) * (1 - t) * sx + 2 * (1 - t) * t * cxc + t * t * ex;
  const y = (1 - t) * (1 - t) * sy + 2 * (1 - t) * t * cyc + t * t * ey;
  const alpha = t < 0.92 ? 1 : (1 - (t - 0.92) / 0.08);
  return (
    <g pointerEvents="none">
      <path
        d={`M${sx},${sy} Q${cxc},${cyc} ${x.toFixed(2)},${y.toFixed(2)}`}
        stroke="#9af0ff"
        strokeWidth="1.2"
        fill="none"
        opacity="0.35"
        strokeDasharray="2 4"
      />
      <circle cx={x} cy={y} r="14" fill="url(#sf-pulse)" opacity={alpha * 0.9} />
      <circle cx={x} cy={y} r="3.8" fill="#ffffff" opacity={alpha} />
      {t < 0.85 && (
        <text x={x + 16} y={y - 8} className="sf-flight-hash" opacity={alpha * 0.85}>
          {shortHash(hashFlight.hash)}
        </text>
      )}
    </g>
  );
}
