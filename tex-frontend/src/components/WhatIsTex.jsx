import React from "react";

/*
  WhatIsTex v14 — selling-points explainer
  ─────────────────────────────────────────
  Five sections, one per top selling point:
    01. Regulator-grade hash-chained evidence
    02. Three-way verdict with first-class abstention
    03. Surface-agnostic content evaluation
    04. OWASP ASI 2026 mapped into every decision
    05. Plug-in to every gateway, not a competitor

  Followed by a short HOW IT WORKS strip (six-layer pipeline)
  and a CTA back to the arcade.

  Tightened hero spacing — the prior version had ~140px of
  vertical air between the headline and the first section.
*/

export default function WhatIsTex({ onBack, onPlayDaily }) {
  return (
    <div className="what-stage">
      <div className="hub-grid-bg" />
      <div className="hub-haze" />

      <div className="what-frame">
        {/* Top bar */}
        <div style={{
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
          paddingBottom: 14,
          borderBottom: "1px solid var(--rule-2)",
          marginBottom: 24,
          gap: 12,
          flexWrap: "wrap",
          paddingTop: 10,
        }}>
          <div style={{ display: "flex", alignItems: "center", gap: 14 }}>
            <HexMark />
            <div style={{ lineHeight: 1.2 }}>
              <div className="display" style={{ fontSize: 20, color: "var(--ink)", letterSpacing: "0.08em" }}>
                WHAT IS TEX
              </div>
              <div className="micro" style={{ color: "var(--ink-faint)" }}>
                AI ACTION GOVERNANCE / VORTEXBLACK
              </div>
            </div>
          </div>
          <button onClick={onBack} className="bail-btn">← BACK</button>
        </div>

        {/* Hero — tighter spacing */}
        <div className="rise" style={{ padding: "16px 0 36px 0" }}>
          <div className="kicker" style={{ color: "var(--cyan)", marginBottom: 14 }}>▸ TEX // AEGIS</div>
          <h1 style={{
            fontFamily: "var(--font-display)",
            fontSize: "clamp(36px, min(6.2vw, 10vh), 80px)",
            lineHeight: 0.92,
            letterSpacing: "-0.005em",
            textTransform: "uppercase",
            margin: 0,
            maxWidth: "100%",
            overflowWrap: "break-word",
          }}>
            THE GATE BETWEEN<br />
            <span style={{
              background: "linear-gradient(90deg, var(--pink) 0%, var(--yellow) 50%, var(--cyan) 100%)",
              backgroundSize: "200% 100%",
              WebkitBackgroundClip: "text",
              backgroundClip: "text",
              WebkitTextFillColor: "transparent",
              animation: "holo-shift 6s ease-in-out infinite",
              filter: "drop-shadow(0 0 20px rgba(255, 61, 122, 0.25))",
            }}>
              AI AND THE REAL WORLD.
            </span>
          </h1>
          <p style={{
            maxWidth: 720,
            color: "var(--ink-dim)",
            fontSize: "clamp(16px, 2vw, 19px)",
            lineHeight: 1.6,
            marginTop: 22,
          }}>
            Identity governance approves the <i>action</i>. Behavior monitoring watches the <i>pattern</i>.
            Neither one looks at the <span style={{ color: "var(--ink)", fontWeight: 600 }}>actual content</span> your
            AI agent is about to release. Tex does — and it produces audit-grade proof of every call.
            Five things make Tex different from everything else in the agent-security space.
          </p>
        </div>

        {/* Section 01 — Hash-chained evidence */}
        <Section
          number="01"
          tint="var(--cyan)"
          title="HASH-CHAINED, REGULATOR-GRADE EVIDENCE"
          body={<>
            Every Tex verdict is HMAC-signed and chained to the one before it. Tamper any link
            and the chain breaks — provably. When the EU AI Act&apos;s August 2026 deadline hits,
            or your SOC 2 auditor asks <i>&ldquo;why did your AI send this&rdquo;</i>, you don&apos;t shrug.
            You hand over a portable evidence bundle with the layer-by-layer reasoning. Decisions
            made through Portkey, MCP, or the SDK all replay against the same audit endpoint.
            <em style={{ color: "var(--ink-faint)" }}> No closed gateway can match this — their evidence is locked to their platform.</em>
          </>}
          visual={<ReceiptVisual />}
        />

        {/* Section 02 — Three verdicts */}
        <Section
          number="02"
          tint="var(--yellow)"
          title="THREE VERDICTS, NOT TWO"
          body={<>
            Every action gets exactly one of three: <b style={{ color: "var(--green)" }}>PERMIT</b> (clean — release),
            &nbsp;<b style={{ color: "var(--yellow)" }}>ABSTAIN</b> (uncertain — escalate to a human),
            &nbsp;<b style={{ color: "var(--red)" }}>FORBID</b> (blocked — never released).
            Binary block/allow systems force a choice between false-positive churn and unsafe
            releases. ABSTAIN is a first-class verdict in Tex — it routes the gray-zone
            content to the one place it belongs: a human reviewer. Your reply rates stay up.
            Your breach risk goes down.
          </>}
          visual={<VerdictsVisual />}
        />

        {/* Section 03 — Surface-agnostic */}
        <Section
          number="03"
          tint="var(--pink)"
          title="EVERY SURFACE, ONE ENGINE"
          body={<>
            Email drafts, API calls, Slack messages, database writes, code deploys, MCP tool
            calls — Tex evaluates the <b>actual content</b> across all of them with the same
            policy engine and the same evidence chain. One integration, every channel.
            When your AI SDR sends 10,000 emails this week, when your support agent posts
            to Slack, when your ops bot writes to Postgres — the verdict comes from the
            same place. No duplicate policies. No surface drift.
          </>}
          visual={<SurfacesVisual />}
        />

        {/* Section 04 — OWASP ASI 2026 */}
        <Section
          number="04"
          tint="var(--green)"
          title="OWASP ASI 2026, MAPPED IN"
          body={<>
            The OWASP Top 10 for Agentic Applications (2026) is the canonical taxonomy
            for AI agent risk: goal hijacking, tool misuse, sensitive disclosure,
            missing guardrails, and seven more. Tex doesn&apos;t just <i>reference</i> ASI — every
            evaluation produces structured findings tagged with the exact ASI codes
            triggered, plus how strongly each one influenced the final verdict. Security
            teams get a real audit artifact. Marketing badge sites get a slide. Tex gives
            you the data behind the slide.
          </>}
          visual={<AsiVisual />}
        />

        {/* Section 05 — Plug-in, not competitor */}
        <Section
          number="05"
          tint="var(--cyan)"
          title="PLUG-IN, NOT REPLACEMENT"
          body={<>
            Tex doesn&apos;t replace your AI gateway. It plugs into it. Native adapters for
            Portkey, LiteLLM, Cloudflare AI Gateway, TrueFoundry, Solo.io, Bedrock,
            Microsoft Copilot Studio, and OpenAI AgentKit — plus an MCP server for
            Cursor / Claude Desktop / any MCP-aware agent. Five-minute config change.
            No code rewrite. The buyer keeps their stack; Tex becomes the content-evaluation
            layer on top of it.
          </>}
          visual={<IntegrationsVisual />}
        />

        {/* HOW IT WORKS — six-layer pipeline */}
        <div style={{
          padding: "60px 0 40px 0",
          borderTop: "1px solid var(--rule-2)",
          marginTop: 40,
        }}>
          <div className="kicker" style={{ color: "var(--cyan)", marginBottom: 14 }}>▸ HOW IT WORKS</div>
          <h2 style={{
            fontFamily: "var(--font-display)",
            fontSize: "clamp(28px, 4vw, 44px)",
            lineHeight: 1.0,
            letterSpacing: "0.02em",
            textTransform: "uppercase",
            margin: "0 0 18px 0",
          }}>
            ONE REQUEST. SIX LAYERS. 178MS.
          </h2>
          <p style={{
            maxWidth: 720,
            color: "var(--ink-dim)",
            fontSize: "clamp(15px, 1.6vw, 17px)",
            lineHeight: 1.6,
            marginBottom: 28,
          }}>
            When your agent is about to act, Tex inspects the actual content through six
            layers in sequence — deterministic recognizers first (cheap, fast), structured
            semantic analysis last (slow, precise). Each layer can fast-path to a verdict.
            Median end-to-end latency is 178ms.
          </p>
          <PipelineStrip />
        </div>

        {/* CTA */}
        <div style={{
          padding: "40px 0 100px 0",
          textAlign: "center",
          borderTop: "1px solid var(--rule-2)",
          marginTop: 40,
        }}>
          <div className="kicker" style={{ color: "var(--pink)", marginBottom: 18 }}>
            ▸ SEE IT IN ACTION
          </div>
          <h2 style={{
            fontFamily: "var(--font-display)",
            fontSize: "clamp(40px, 6vw, 76px)",
            lineHeight: 0.92,
            letterSpacing: "-0.005em",
            textTransform: "uppercase",
            margin: "0 0 28px 0",
          }}>
            WORK A SHIFT.<br />
            <span style={{ color: "var(--ink-mid)" }}>SEE WHAT TEX SEES.</span>
          </h2>
          <button onClick={onPlayDaily} className="btn-cta breathe">
            ▸ START SHIFT
            <Arrow />
          </button>
        </div>
      </div>
    </div>
  );
}

function Section({ number, title, body, visual, tint }) {
  return (
    <div className="what-section">
      <div>
        <div className="what-num" style={tint ? { color: tint } : undefined}>▸ {number}</div>
        <h2 className="what-h">{title}</h2>
        <div className="what-body">{body}</div>
      </div>
      <div>{visual}</div>
    </div>
  );
}

/* ─── Visuals ─────────────────────────────────────────────────────── */

function ReceiptVisual() {
  return (
    <div style={{
      maxWidth: 460,
      margin: "0 auto",
      width: "100%",
      background: "var(--bg-panel)",
      border: "1px solid var(--rule-cyan)",
      borderRadius: 4,
      padding: 18,
      fontFamily: "var(--font-mono)",
      fontSize: 11,
      lineHeight: 1.7,
    }}>
      <div className="micro" style={{ color: "var(--cyan)", marginBottom: 12 }}>
        ▸ TEX PERMIT TOKEN
      </div>
      <div style={{ color: "var(--ink-mid)" }}>
        <div><span style={{ color: "var(--ink-faint)" }}>action_id:</span> <span style={{ color: "var(--ink)" }}>act_4f8a1c…</span></div>
        <div><span style={{ color: "var(--ink-faint)" }}>verdict:</span> <span style={{ color: "var(--red)" }}>FORBID</span></div>
        <div><span style={{ color: "var(--ink-faint)" }}>layer:</span> <span style={{ color: "var(--ink)" }}>semantic_intent</span></div>
        <div><span style={{ color: "var(--ink-faint)" }}>reason:</span> <span style={{ color: "var(--ink)" }}>internal_pricing_disclosure</span></div>
        <div><span style={{ color: "var(--ink-faint)" }}>evidence:</span> <span style={{ color: "var(--ink-dim)" }}>&quot;30% lower&quot; → competitor_quote</span></div>
        <div><span style={{ color: "var(--ink-faint)" }}>asi_codes:</span> <span style={{ color: "var(--ink)" }}>ASI05, ASI09</span></div>
        <div><span style={{ color: "var(--ink-faint)" }}>latency:</span> <span style={{ color: "var(--cyan)" }}>178ms</span></div>
        <div><span style={{ color: "var(--ink-faint)" }}>chain_prev:</span> <span style={{ color: "var(--ink-dim)" }}>0x9f3c…a8</span></div>
        <div><span style={{ color: "var(--ink-faint)" }}>hmac:</span> <span style={{ color: "var(--ink-dim)" }}>0x4a91…7b</span></div>
      </div>
      <div style={{
        marginTop: 14,
        paddingTop: 12,
        borderTop: "1px solid var(--rule-2)",
        color: "var(--cyan)",
        fontSize: 10,
        letterSpacing: "0.14em",
        textTransform: "uppercase",
      }}>
        ✓ TAMPER-EVIDENT · AUDIT-READY · PORTABLE
      </div>
    </div>
  );
}

function VerdictsVisual() {
  const items = [
    { v: "PERMIT", c: "var(--green)", body: "Status check email — clean.", glyph: "✓" },
    { v: "ABSTAIN", c: "var(--yellow)", body: "Refund language unclear — escalate.", glyph: "?" },
    { v: "FORBID", c: "var(--red)", body: "Internal pricing in outbound email.", glyph: "✕" },
  ];
  return (
    <div style={{
      display: "flex",
      flexDirection: "column",
      gap: 14,
      maxWidth: 460,
      margin: "0 auto",
      width: "100%",
    }}>
      {items.map((it) => (
        <div key={it.v} style={{
          padding: "16px 18px",
          background: "var(--bg-panel)",
          border: `1px solid ${it.c}`,
          borderRadius: 4,
          position: "relative",
        }}>
          <div style={{ display: "flex", alignItems: "center", gap: 14 }}>
            <div style={{
              width: 36, height: 36,
              borderRadius: "50%",
              border: `1.5px solid ${it.c}`,
              display: "flex", alignItems: "center", justifyContent: "center",
              fontSize: 18, color: it.c,
              fontWeight: 700,
              flexShrink: 0,
            }}>
              {it.glyph}
            </div>
            <div style={{ flex: 1, minWidth: 0 }}>
              <div className="display" style={{ color: it.c, fontSize: 24, letterSpacing: "0.08em" }}>
                ▸ {it.v}
              </div>
              <div className="mono" style={{ color: "var(--ink-dim)", fontSize: 12, marginTop: 4 }}>
                {it.body}
              </div>
            </div>
          </div>
        </div>
      ))}
    </div>
  );
}

function SurfacesVisual() {
  const surfaces = [
    { n: "EMAIL",    d: "Outbound drafts before send" },
    { n: "API",      d: "POSTs / webhooks / tool calls" },
    { n: "SLACK",    d: "Channel + DM messages" },
    { n: "DATABASE", d: "INSERT / UPDATE / DELETE" },
    { n: "DEPLOY",   d: "PRs, merges, prod pushes" },
    { n: "MCP",      d: "Any MCP-aware agent client" },
  ];
  return (
    <div style={{
      maxWidth: 460,
      margin: "0 auto",
      width: "100%",
      padding: 16,
      background: "var(--bg-panel)",
      border: "1px solid rgba(255, 61, 122, 0.30)",
      borderRadius: 4,
    }}>
      <div className="micro" style={{ color: "var(--pink)", marginBottom: 12 }}>
        ▸ ONE ENGINE · SIX SURFACES
      </div>
      <div style={{
        display: "grid",
        gridTemplateColumns: "1fr 1fr",
        gap: 8,
      }}>
        {surfaces.map((s) => (
          <div key={s.n} style={{
            padding: "12px 12px",
            background: "var(--bg-card)",
            border: "1px solid var(--rule-2)",
            borderRadius: 3,
          }}>
            <div className="display" style={{ color: "var(--pink)", fontSize: 14, letterSpacing: "0.08em" }}>
              {s.n}
            </div>
            <div className="mono" style={{ color: "var(--ink-faint)", fontSize: 10, marginTop: 4 }}>
              {s.d}
            </div>
          </div>
        ))}
      </div>
      <div style={{
        marginTop: 12,
        padding: "8px 12px",
        background: "rgba(255, 61, 122, 0.06)",
        border: "1px solid rgba(255, 61, 122, 0.30)",
        borderRadius: 3,
        textAlign: "center",
        color: "var(--pink)",
        fontFamily: "var(--font-mono)",
        fontSize: 11,
        letterSpacing: "0.16em",
        textTransform: "uppercase",
      }}>
        ONE POLICY · ONE EVIDENCE CHAIN
      </div>
    </div>
  );
}

function AsiVisual() {
  const codes = [
    { code: "ASI01", label: "Behavior Hijacking",     hit: false },
    { code: "ASI02", label: "Tool Misuse",            hit: false },
    { code: "ASI03", label: "Privilege Abuse",        hit: false },
    { code: "ASI04", label: "Missing Guardrails",     hit: true  },
    { code: "ASI05", label: "Unexpected Code Exec.",  hit: true  },
    { code: "ASI06", label: "Resource Exhaustion",    hit: false },
    { code: "ASI07", label: "Supply Chain",           hit: false },
    { code: "ASI08", label: "Prompt Injection",       hit: false },
    { code: "ASI09", label: "Sensitive Disclosure",   hit: true  },
    { code: "ASI10", label: "Over-reliance",          hit: false },
  ];
  return (
    <div style={{
      maxWidth: 460,
      margin: "0 auto",
      width: "100%",
      padding: 16,
      background: "var(--bg-panel)",
      border: "1px solid rgba(95, 250, 159, 0.30)",
      borderRadius: 4,
    }}>
      <div className="micro" style={{ color: "var(--green)", marginBottom: 12 }}>
        ▸ OWASP ASI 2026 · STRUCTURED FINDINGS
      </div>
      <div style={{
        display: "grid",
        gridTemplateColumns: "1fr 1fr",
        gap: 6,
      }}>
        {codes.map((c) => (
          <div key={c.code} style={{
            padding: "8px 10px",
            background: c.hit ? "rgba(95, 250, 159, 0.10)" : "var(--bg-card)",
            border: c.hit ? "1px solid var(--green)" : "1px solid var(--rule-2)",
            borderRadius: 3,
            display: "flex",
            alignItems: "center",
            gap: 8,
          }}>
            <span className="display" style={{
              color: c.hit ? "var(--green)" : "var(--ink-faint)",
              fontSize: 11,
              letterSpacing: "0.08em",
              flexShrink: 0,
            }}>
              {c.code}
            </span>
            <span className="mono" style={{
              color: c.hit ? "var(--ink)" : "var(--ink-faint)",
              fontSize: 9,
              flex: 1,
              minWidth: 0,
              overflow: "hidden",
              textOverflow: "ellipsis",
              whiteSpace: "nowrap",
            }}>
              {c.label}
            </span>
          </div>
        ))}
      </div>
      <div style={{
        marginTop: 12,
        padding: "8px 12px",
        background: "rgba(95, 250, 159, 0.06)",
        border: "1px solid rgba(95, 250, 159, 0.30)",
        borderRadius: 3,
        textAlign: "center",
        color: "var(--green)",
        fontFamily: "var(--font-mono)",
        fontSize: 11,
        letterSpacing: "0.16em",
        textTransform: "uppercase",
      }}>
        3 CODES TRIGGERED · ALL IN RECEIPT
      </div>
    </div>
  );
}

function IntegrationsVisual() {
  const integrations = [
    "PORTKEY", "LITELLM", "CLOUDFLARE", "TRUEFOUNDRY",
    "SOLO.IO", "BEDROCK", "COPILOT STUDIO", "AGENTKIT",
    "MCP SERVER", "REST API", "PYTHON SDK", "WEBHOOK",
  ];
  return (
    <div style={{
      maxWidth: 460,
      margin: "0 auto",
      width: "100%",
      padding: 16,
      background: "var(--bg-panel)",
      border: "1px solid var(--rule-cyan)",
      borderRadius: 4,
    }}>
      <div className="micro" style={{ color: "var(--cyan)", marginBottom: 12 }}>
        ▸ NATIVE INTEGRATIONS
      </div>
      <div style={{
        display: "grid",
        gridTemplateColumns: "1fr 1fr",
        gap: 6,
      }}>
        {integrations.map((name) => (
          <div key={name} style={{
            padding: "10px 12px",
            background: "var(--bg-card)",
            border: "1px solid var(--rule-2)",
            borderRadius: 3,
            color: "var(--cyan)",
            fontFamily: "var(--font-display)",
            fontSize: 12,
            letterSpacing: "0.08em",
          }}>
            {name}
          </div>
        ))}
      </div>
      <div style={{
        marginTop: 12,
        padding: "8px 12px",
        background: "rgba(95, 240, 255, 0.06)",
        border: "1px solid var(--rule-cyan)",
        borderRadius: 3,
        textAlign: "center",
        color: "var(--cyan)",
        fontFamily: "var(--font-mono)",
        fontSize: 11,
        letterSpacing: "0.16em",
        textTransform: "uppercase",
        fontWeight: 700,
      }}>
        5-MINUTE CONFIG CHANGE
      </div>
    </div>
  );
}

function PipelineStrip() {
  const layers = [
    { l: "DETERMINISTIC", d: "Regex / known-bad / forbidden patterns" },
    { l: "RETRIEVAL",     d: "Policy clauses, precedents, entities" },
    { l: "SPECIALISTS",   d: "PII, secrets, financial, code judges" },
    { l: "SEMANTIC",      d: "Structured intent + claim analysis" },
    { l: "FUSION/ROUTER", d: "Score combine → P / A / F verdict" },
    { l: "EVIDENCE",      d: "HMAC-sign + chain-link receipt" },
  ];
  return (
    <div style={{
      display: "grid",
      gridTemplateColumns: "repeat(auto-fit, minmax(200px, 1fr))",
      gap: 10,
    }}>
      {layers.map((layer, i) => (
        <div key={i} style={{
          padding: "12px 14px",
          background: "var(--bg-panel)",
          border: "1px solid var(--rule-2)",
          borderRadius: 3,
        }}>
          <div className="display" style={{ color: "var(--cyan)", fontSize: 13, letterSpacing: "0.08em" }}>
            0{i + 1} · {layer.l}
          </div>
          <div className="mono" style={{ color: "var(--ink-faint)", fontSize: 11, marginTop: 4 }}>
            {layer.d}
          </div>
        </div>
      ))}
    </div>
  );
}

function HexMark() {
  return (
    <div style={{
      width: 28, height: 32,
      filter: "drop-shadow(0 0 8px var(--pink-soft))",
    }}>
      <svg viewBox="0 0 28 32" width="100%" height="100%">
        <polygon points="14,2 26,9 26,23 14,30 2,23 2,9" fill="none" stroke="var(--pink)" strokeWidth="1.5" />
        <polygon points="14,8 21,12 21,20 14,24 7,20 7,12" fill="var(--pink)" />
      </svg>
    </div>
  );
}

function Arrow() {
  return (
    <svg width="20" height="14" viewBox="0 0 20 14" fill="none">
      <path d="M0 7H18M18 7L12 1M18 7L12 13" stroke="currentColor" strokeWidth="2" strokeLinecap="square" />
    </svg>
  );
}
