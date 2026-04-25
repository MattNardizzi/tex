import React from "react";
import { OWASP_ASI, ASI_ORDER, asiUrl, OWASP_ASI_URL } from "../lib/owaspAsi.js";
import { incidentsByAsi } from "../lib/incidents.js";
import ComplianceStrip from "./ComplianceStrip.jsx";

/*
  AsiPage — /asi route.

  This is the SEO + analyst + citation magnet. A public page that maps
  every OWASP ASI 2026 category to one or more Tex incidents, with a
  "TRY THIS ATTACK" button that drops the visitor straight into a round.

  Positioning: this page exists to claim the phrase "OWASP ASI 2026
  reference adjudicator" before any incumbent does.
*/

export default function AsiPage({ onTryIncident, onClose, onOpenDevelopers, onOpenBuyer }) {
  return (
    <div style={{ minHeight: "100vh", display: "flex", flexDirection: "column" }}>
      {/* Header */}
      <header style={{
        borderBottom: "1px solid var(--hairline-2)",
        padding: "14px 32px",
        display: "flex",
        alignItems: "center",
        justifyContent: "space-between",
        background: "rgba(6, 7, 14, 0.6)",
        backdropFilter: "blur(10px)",
        position: "sticky",
        top: 0,
        zIndex: 10,
      }}>
        <div style={{ display: "flex", alignItems: "center", gap: 14 }}>
          <button onClick={onClose} className="micro" style={{
            color: "var(--ink-faint)",
            padding: "6px 10px",
            border: "1px solid var(--hairline-2)",
            borderRadius: 4,
          }}>
            ← TEX ARENA
          </button>
          <span className="display" style={{ fontSize: 17, letterSpacing: "0.06em" }}>
            TEX × OWASP ASI 2026
          </span>
        </div>
        <div style={{ display: "flex", gap: 8 }}>
          <button onClick={onOpenDevelopers} className="micro" style={{
            color: "var(--cyan)",
            padding: "6px 10px",
            border: "1px solid rgba(95, 240, 255, 0.35)",
            borderRadius: 4,
          }}>
            FOR ENGINEERING →
          </button>
          <button onClick={onOpenBuyer} className="micro" style={{
            color: "var(--ink-dim)",
            padding: "6px 10px",
            border: "1px solid var(--hairline-2)",
            borderRadius: 4,
          }}>
            FOR SECURITY TEAMS →
          </button>
        </div>
      </header>

      {/* Hero */}
      <section style={{ padding: "56px 48px 32px", maxWidth: 1100, margin: "0 auto", width: "100%" }}>
        <div className="kicker" style={{ color: "var(--cyan)", marginBottom: 12 }}>
          OWASP AGENTIC SECURITY INITIATIVE · TOP 10 · 2026
        </div>
        <h1 className="display" style={{ fontSize: "clamp(48px, 7vw, 88px)", lineHeight: 0.95, margin: 0 }}>
          THE OWASP ASI 2026
          <br />
          <span className="glow-cyan" style={{ color: "var(--cyan)" }}>REFERENCE ADJUDICATOR.</span>
        </h1>
        <p style={{ marginTop: 22, fontSize: 17, color: "var(--ink-dim)", maxWidth: 780, lineHeight: 1.55 }}>
          Tex is a content-layer adjudication gate for AI agents.
          Every PERMIT / ABSTAIN / FORBID verdict is mapped to one or more
          OWASP ASI 2026 categories — with cryptographically signed evidence
          your auditor can verify offline. Below: each category, the Tex
          incidents that exercise it, and a button to try the attack live.
        </p>
        <div style={{ marginTop: 22 }}>
          <a
            href={OWASP_ASI_URL}
            target="_blank"
            rel="noreferrer"
            className="btn-ghost"
          >
            OWASP ASI INITIATIVE →
          </a>
        </div>
      </section>

      {/* Compliance band */}
      <section style={{
        padding: "20px 48px",
        borderTop: "1px solid var(--hairline-2)",
        borderBottom: "1px solid var(--hairline-2)",
        background: "var(--bg-1)",
      }}>
        <div style={{ maxWidth: 1100, margin: "0 auto", width: "100%" }}>
          <div className="kicker" style={{ color: "var(--ink-faint)", marginBottom: 10 }}>
            EVIDENCE COVERAGE
          </div>
          <ComplianceStrip />
        </div>
      </section>

      {/* The 10 categories */}
      <section style={{ padding: "40px 48px", maxWidth: 1100, margin: "0 auto", width: "100%" }}>
        <div className="kicker" style={{ color: "var(--cyan)", marginBottom: 16 }}>
          THE 10 CATEGORIES
        </div>
        <div style={{ display: "grid", gap: 16 }}>
          {ASI_ORDER.map((code) => (
            <CategoryRow
              key={code}
              code={code}
              meta={OWASP_ASI[code]}
              incidents={incidentsByAsi(code)}
              onTry={onTryIncident}
            />
          ))}
        </div>
      </section>

      {/* Footer */}
      <section style={{
        borderTop: "1px solid var(--hairline-2)",
        padding: "32px 48px",
        background: "linear-gradient(180deg, transparent, rgba(255, 225, 74, 0.03))",
      }}>
        <div style={{ maxWidth: 1100, margin: "0 auto", width: "100%" }}>
          <div className="display" style={{ fontSize: 28, lineHeight: 1.05 }}>
            EVERY VERDICT.{" "}
            <span className="glow-yellow" style={{ color: "var(--yellow)" }}>EVERY CATEGORY.</span>{" "}
            EVERY TIME.
          </div>
          <p style={{ marginTop: 10, color: "var(--ink-dim)", fontSize: 14, maxWidth: 780, lineHeight: 1.55 }}>
            Tex is the only public adjudication gate for AI agents that
            attributes every verdict to specific OWASP ASI 2026 categories
            and produces SHA-256 hash-chained, HMAC-signed evidence on every
            decision.
          </p>
          <div style={{ marginTop: 18, display: "flex", gap: 10, flexWrap: "wrap" }}>
            <button onClick={onClose} className="btn-primary">
              STEP IN THE RING →
            </button>
            <button onClick={onOpenDevelopers} className="btn-ghost">
              GET API ACCESS
            </button>
            <button onClick={onOpenBuyer} className="btn-ghost">
              FOR SECURITY TEAMS
            </button>
          </div>
          <div className="micro" style={{ color: "var(--ink-faint)", marginTop: 24 }}>
            BUILT BY VORTEXBLACK · TEXAEGIS.COM
          </div>
        </div>
      </section>
    </div>
  );
}

function CategoryRow({ code, meta, incidents, onTry }) {
  if (!meta) return null;
  return (
    <div className="panel" style={{ padding: "20px 22px" }}>
      <div style={{ display: "flex", alignItems: "baseline", gap: 14, flexWrap: "wrap" }}>
        <span className="display" style={{ fontSize: 22, color: "var(--cyan)" }}>
          {code}
        </span>
        <span className="display" style={{ fontSize: 22, color: "var(--ink)" }}>
          {meta.title}
        </span>
        <a
          href={asiUrl(code)}
          target="_blank"
          rel="noreferrer"
          className="micro"
          style={{ color: "var(--ink-faint)", marginLeft: "auto", textDecoration: "underline" }}
        >
          OWASP ↗
        </a>
      </div>
      <div style={{ marginTop: 8, color: "var(--ink-dim)", fontSize: 14, lineHeight: 1.55 }}>
        {meta.long}
      </div>
      {incidents.length > 0 && (
        <div style={{
          marginTop: 14,
          paddingTop: 14,
          borderTop: "1px solid var(--hairline)",
        }}>
          <div className="kicker" style={{ color: "var(--ink-faint)", marginBottom: 10 }}>
            INCIDENTS THAT EXERCISE THIS CATEGORY
          </div>
          <div style={{ display: "flex", flexWrap: "wrap", gap: 8 }}>
            {incidents.map((inc) => (
              <button
                key={inc.id}
                onClick={() => onTry(inc.id)}
                style={{
                  padding: "8px 12px",
                  border: "1px solid var(--hairline-2)",
                  borderRadius: 4,
                  background: "var(--bg-2)",
                  cursor: "pointer",
                  textAlign: "left",
                }}
              >
                <span className="mono" style={{ fontSize: 11, color: "var(--pink)", fontWeight: 600 }}>
                  {inc.name}
                </span>
                <span className="micro" style={{ fontSize: 9, color: "var(--ink-faint)", marginLeft: 8 }}>
                  TRY THIS ATTACK →
                </span>
              </button>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
