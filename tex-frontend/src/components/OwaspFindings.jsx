import React, { useState } from "react";
import { OWASP_ASI, asiUrl, normalizeAsiCode } from "../lib/owaspAsi.js";

/*
  OwaspFindings — replaces the old "WHY TEX CAUGHT IT" panel.

  Every Tex verdict is mapped to one or more OWASP ASI 2026 categories.
  This panel makes that explicit. Each chip:
    - shows the ASI code
    - shows the canonical OWASP title
    - expands inline to show the description + link to OWASP

  Positioning: this is the moment a player sees that Tex isn't just a
  classifier — it's the OWASP ASI 2026 reference adjudicator.
*/

export default function OwaspFindings({ findings = [], verdict }) {
  const [open, setOpen] = useState(null);

  // Group findings by canonical ASI code, dedupe.
  const byCode = new Map();
  findings.forEach((f) => {
    const code =
      normalizeAsiCode(f.short_code) ||
      normalizeAsiCode(f.category) ||
      null;
    if (!code) return;
    if (!byCode.has(code)) {
      byCode.set(code, {
        code,
        title: OWASP_ASI[code]?.title || f.title || code,
        backendTitles: new Set(),
        maxConfidence: f.confidence || 0,
        maxSeverity: f.severity || 0,
      });
    }
    const entry = byCode.get(code);
    if (f.title) entry.backendTitles.add(f.title);
    entry.maxConfidence = Math.max(entry.maxConfidence, f.confidence || 0);
    entry.maxSeverity = Math.max(entry.maxSeverity, f.severity || 0);
  });

  const codes = [...byCode.values()];

  if (codes.length === 0) {
    // Even with no findings, show the ASI compliance footer so the
    // OWASP framing is always visible.
    return (
      <div style={{ marginBottom: 20 }}>
        <div className="kicker" style={{ color: "var(--cyan)", marginBottom: 8 }}>
          OWASP ASI 2026 FINDINGS
        </div>
        <div style={{
          padding: "10px 14px",
          border: "1px solid var(--hairline-2)",
          borderRadius: 6,
          background: "var(--bg-2)",
          color: "var(--ink-faint)",
          fontSize: 12,
        }}>
          No ASI categories triggered on this attempt.
        </div>
        <Footer />
      </div>
    );
  }

  return (
    <div style={{ marginBottom: 20 }}>
      <div style={{
        display: "flex",
        alignItems: "baseline",
        justifyContent: "space-between",
        marginBottom: 8,
        flexWrap: "wrap",
        gap: 8,
      }}>
        <span className="kicker" style={{ color: "var(--cyan)" }}>
          OWASP ASI 2026 FINDINGS
        </span>
        <span className="micro" style={{ color: "var(--ink-faint)" }}>
          {verdict === "PERMIT" ? "WHAT GOT THROUGH" : "WHAT TEX CAUGHT"}
        </span>
      </div>

      <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
        {codes.map((c) => {
          const isOpen = open === c.code;
          const meta = OWASP_ASI[c.code];
          return (
            <button
              key={c.code}
              onClick={() => setOpen(isOpen ? null : c.code)}
              style={{
                padding: "6px 10px",
                border: `1px solid ${isOpen ? "var(--cyan)" : "var(--hairline-2)"}`,
                borderRadius: 4,
                background: isOpen
                  ? "rgba(95, 240, 255, 0.08)"
                  : "rgba(95, 240, 255, 0.03)",
                cursor: "pointer",
                textAlign: "left",
              }}
              aria-expanded={isOpen}
            >
              <span className="mono" style={{ fontSize: 11, color: "var(--cyan)", fontWeight: 600 }}>
                {c.code}
              </span>
              <span className="mono" style={{ fontSize: 11, color: "var(--ink-dim)", marginLeft: 6 }}>
                {meta?.title || c.title}
              </span>
            </button>
          );
        })}
      </div>

      {open && OWASP_ASI[open] && (
        <div className="rise" style={{
          marginTop: 10,
          padding: "12px 14px",
          border: "1px solid rgba(95, 240, 255, 0.3)",
          borderRadius: 6,
          background: "rgba(95, 240, 255, 0.04)",
        }}>
          <div className="mono" style={{ fontSize: 11, color: "var(--cyan)", fontWeight: 600 }}>
            {open} · {OWASP_ASI[open].title}
          </div>
          <div style={{ fontSize: 13, color: "var(--ink-dim)", marginTop: 6, lineHeight: 1.55 }}>
            {OWASP_ASI[open].long}
          </div>
          <a
            href={asiUrl(open)}
            target="_blank"
            rel="noreferrer"
            className="micro"
            style={{
              display: "inline-block",
              marginTop: 10,
              color: "var(--cyan)",
              textDecoration: "underline",
            }}
          >
            VIEW ON OWASP →
          </a>
        </div>
      )}

      <Footer />
    </div>
  );
}

function Footer() {
  return (
    <div className="micro" style={{
      marginTop: 8,
      color: "var(--ink-faint)",
      fontSize: 10,
    }}>
      TEX IS THE OWASP ASI 2026 REFERENCE ADJUDICATOR · EVERY VERDICT MAPPED
    </div>
  );
}
