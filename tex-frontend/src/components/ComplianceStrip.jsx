import React from "react";

/*
  ComplianceStrip — the single visual artifact that resolves the
  CISO/engineering-leader split. Every framework Tex maps to, side by
  side. Quietly reassuring without changing the page's voice.
*/

const FRAMEWORKS = [
  { code: "OWASP ASI", detail: "2026 reference" },
  { code: "NIST AI RMF", detail: "controls + evidence" },
  { code: "ISO 42001", detail: "AI MS audit-ready" },
  { code: "EU AI ACT", detail: "Art. 50 · Aug 2 2026" },
  { code: "FINRA", detail: "Rule 2210 + AI-washing" },
  { code: "HIPAA", detail: "PHI guardrails" },
];

export default function ComplianceStrip({ compact = false }) {
  return (
    <div style={{
      display: "grid",
      gridTemplateColumns: "repeat(6, minmax(0, 1fr))",
      gap: compact ? 4 : 8,
    }} className="compliance-grid">
      {FRAMEWORKS.map((f) => (
        <div
          key={f.code}
          style={{
            padding: compact ? "8px 8px" : "10px 12px",
            border: "1px solid var(--hairline-2)",
            borderRadius: 4,
            background: "var(--bg-2)",
            textAlign: "left",
            minWidth: 0,
          }}
        >
          <div className="mono" style={{
            fontSize: 10,
            color: "var(--green)",
            fontWeight: 600,
            letterSpacing: "0.06em",
            whiteSpace: "nowrap",
            overflow: "hidden",
            textOverflow: "ellipsis",
          }}>
            ✓ {f.code}
          </div>
          {!compact && (
            <div className="micro" style={{
              fontSize: 9,
              color: "var(--ink-faint)",
              marginTop: 3,
              lineHeight: 1.3,
            }}>
              {f.detail}
            </div>
          )}
        </div>
      ))}

      <style>{`
        @media (max-width: 760px) {
          .compliance-grid { grid-template-columns: repeat(3, 1fr) !important; }
        }
      `}</style>
    </div>
  );
}
