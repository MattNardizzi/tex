import React from "react";
import { X, BookOpen } from "lucide-react";
import { formatPercent } from "../lib/formatters";

export default function Dojo({ decision, round, onClose }) {
  if (!decision) {
    return (
      <Shell onClose={onClose} title="The Dojo">
        <div className="p-8 text-center">
          <p className="font-accent italic text-[18px] text-ink-mid">
            Throw a punch first. The Dojo reviews what actually happened.
          </p>
        </div>
      </Shell>
    );
  }

  const specialists = decision.specialists?.specialists ?? [];
  const semantic = decision.semantic || { dimensions: {}, overall_confidence: 0 };
  const semanticDimensions = Object.entries(semantic.dimensions || {});

  return (
    <Shell onClose={onClose} title="The Dojo">
      <div className="max-h-[85vh] overflow-y-auto safe-bottom">
        <div className="px-5 py-4 border-b-2 border-ink bg-paper-dim">
          <div className="font-mono text-[10px] uppercase tracking-[0.26em] text-ink-mid">
            Round {round.id} · {round.name}
          </div>
          <h3 className="font-display font-black text-[24px] leading-tight text-ink mt-1">
            How Tex decided.
          </h3>
          <p className="font-accent italic text-[15px] text-ink-mid mt-1">
            Four layers voted. Here is the raw tally.
          </p>
        </div>

        {/* Specialists */}
        <Section title="Risk Judges" sub="Four heuristic specialists, each scoring one kind of risk">
          {specialists.length === 0 ? (
            <Empty>No specialist fired on this content.</Empty>
          ) : (
            <ul className="divide-y divide-ink/10">
              {specialists.map((s, i) => (
                <SpecialistRow key={i} data={s} />
              ))}
            </ul>
          )}
        </Section>

        {/* Semantic dimensions */}
        <Section
          title="Semantic Dimensions"
          sub="The LLM judge scores five independent risk dimensions"
        >
          {semanticDimensions.length === 0 ? (
            <Empty>Semantic layer returned no dimensions.</Empty>
          ) : (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3 p-4">
              {semanticDimensions.map(([key, dim]) => (
                <DimensionCard key={key} name={key} data={dim} />
              ))}
            </div>
          )}
          <div className="px-4 pb-4 pt-2 border-t border-ink/10 flex items-center justify-between">
            <span className="font-mono text-[10px] uppercase tracking-[0.22em] text-ink-mid">
              Semantic verdict
            </span>
            <span className="font-display font-bold text-ink">
              {semantic.recommended_verdict || "—"}
            </span>
            <span className="font-mono text-[11px] text-ink-mid">
              conf. {formatPercent(semantic.overall_confidence)}
            </span>
          </div>
        </Section>

        {/* Retrieval */}
        <Section
          title="Retrieval Context"
          sub="Policy clauses, sensitive entities, and matched precedents used to ground the call"
        >
          <RetrievalBlock retrieval={decision.retrieval} />
        </Section>

        {/* Evidence */}
        <Section title="Evidence Chain" sub="SHA-256 hash-chained audit record">
          <div className="p-4">
            <div className="font-mono text-[10px] uppercase tracking-[0.22em] text-ink-mid mb-1">
              Hash
            </div>
            <div className="font-mono text-[11px] text-ink break-all bg-paper-dim border border-ink/15 px-2 py-1.5">
              {decision.evidence.evidence_hash || "—"}
            </div>
            <div className="mt-2 flex items-center gap-4 font-mono text-[11px] text-ink-mid">
              <span>
                valid: <strong className="text-ink">{decision.evidence.chain_valid ? "yes" : "no"}</strong>
              </span>
              <span>
                records: <strong className="text-ink">{decision.evidence.record_count}</strong>
              </span>
            </div>
          </div>
        </Section>

        {/* Lesson */}
        <div className="px-5 py-5 bg-ink text-paper border-t-2 border-ink">
          <div className="flex items-center gap-2 mb-2">
            <BookOpen className="w-4 h-4 text-signal" />
            <span className="font-mono text-[10px] uppercase tracking-[0.28em]">
              Takeaway
            </span>
          </div>
          <p className="font-accent italic text-[18px] leading-snug text-paper-dim">
            {buildLesson(decision)}
          </p>
        </div>
      </div>
    </Shell>
  );
}

// ─────────────────────────────────────────────────────────────────────

function Shell({ onClose, title, children }) {
  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center p-3 sm:p-4 bg-arcade-bg/90 backdrop-blur-sm safe-top"
      onClick={onClose}
    >
      <div
        className="relative w-full max-w-[760px] bg-paper border-2 border-ink ink-shadow"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-center justify-between px-5 py-3 border-b-2 border-ink bg-ink text-paper">
          <div className="flex items-baseline gap-3">
            <span className="font-mono text-[10px] uppercase tracking-[0.28em] text-paper-dim">
              道場
            </span>
            <span className="font-display font-black text-[18px]">{title}</span>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 hover:bg-paper/10 rounded-full"
          >
            <X className="w-4 h-4" />
          </button>
        </div>
        {children}
      </div>
    </div>
  );
}

function Section({ title, sub, children }) {
  return (
    <section className="border-b-2 border-ink">
      <div className="px-5 py-3 bg-paper-dim border-b border-ink/15">
        <div className="font-mono text-[10px] uppercase tracking-[0.28em] text-ink">
          {title}
        </div>
        <div className="font-accent italic text-[13px] text-ink-mid mt-0.5">
          {sub}
        </div>
      </div>
      {children}
    </section>
  );
}

function Empty({ children }) {
  return (
    <div className="px-5 py-6 text-center font-accent italic text-[14px] text-ink-faint">
      {children}
    </div>
  );
}

function SpecialistRow({ data }) {
  const risk = typeof data.risk_score === "number" ? data.risk_score : 0;
  const riskPct = Math.round(risk * 100);
  const isHot = risk >= 0.5;
  return (
    <li className="px-4 py-3">
      <div className="flex items-center justify-between gap-3">
        <span className="font-mono text-[12px] text-ink font-bold">
          {data.specialist_name}
        </span>
        <span className="flex items-center gap-2">
          <span
            className={`font-mono text-[11px] font-bold ${
              isHot ? "text-signal" : "text-ink-mid"
            }`}
          >
            {riskPct}
          </span>
          <span className="font-mono text-[10px] text-ink-faint">
            conf {formatPercent(data.confidence, 0)}
          </span>
        </span>
      </div>
      <div className="mt-1.5 h-1.5 bg-ink/10 relative">
        <div
          className={`absolute inset-y-0 left-0 ${isHot ? "bg-signal" : "bg-ink"}`}
          style={{ width: `${Math.min(100, riskPct)}%` }}
        />
      </div>
      {data.summary && (
        <p className="mt-1.5 text-[12px] text-ink-mid leading-[1.5]">
          {data.summary}
        </p>
      )}
      {data.evidence && data.evidence.length > 0 && (
        <div className="mt-1.5 flex flex-wrap gap-1">
          {data.evidence.slice(0, 6).map((e, i) => (
            <span
              key={i}
              className="font-mono text-[10px] px-1.5 py-0.5 bg-signal-soft border border-signal/30 text-signal-deep"
            >
              {e.keyword || e.text}
            </span>
          ))}
        </div>
      )}
    </li>
  );
}

function DimensionCard({ name, data }) {
  const score = typeof data.score === "number" ? data.score : 0;
  const pct = Math.round(score * 100);
  const hot = score >= 0.5;
  return (
    <div className={`border-2 p-3 ${hot ? "border-signal" : "border-ink/25"}`}>
      <div className="flex items-baseline justify-between mb-1">
        <span className="font-mono text-[11px] uppercase tracking-[0.16em] text-ink font-bold">
          {name.replace(/_/g, " ")}
        </span>
        <span
          className={`font-display font-black text-[20px] leading-none ${
            hot ? "text-signal" : "text-ink"
          }`}
        >
          {pct}
        </span>
      </div>
      <div className="h-1 bg-ink/10 mb-1.5">
        <div
          className={`h-full ${hot ? "bg-signal" : "bg-ink"}`}
          style={{ width: `${pct}%` }}
        />
      </div>
      <div className="font-mono text-[9px] uppercase tracking-[0.2em] text-ink-faint">
        conf {formatPercent(data.confidence, 0)}
      </div>
      {data.evidence_spans && data.evidence_spans.length > 0 && (
        <div className="mt-2 pt-2 border-t border-ink/10">
          {data.evidence_spans.slice(0, 2).map((span, i) => (
            <div
              key={i}
              className="font-mono text-[10px] text-ink-mid italic leading-snug"
            >
              "{span.text}"
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

function RetrievalBlock({ retrieval }) {
  if (!retrieval || retrieval.is_empty) {
    return <Empty>No retrieval context was grounded for this call.</Empty>;
  }
  const { clauses = [], entities = [] } = retrieval;
  if (clauses.length === 0 && entities.length === 0) {
    return <Empty>Retrieval ran but found no relevant context.</Empty>;
  }
  return (
    <div className="p-4 space-y-3">
      {clauses.length > 0 && (
        <div>
          <div className="font-mono text-[10px] uppercase tracking-[0.22em] text-ink-mid mb-1.5">
            Matched policy clauses ({clauses.length})
          </div>
          <ul className="space-y-1">
            {clauses.slice(0, 6).map((c, i) => (
              <li
                key={i}
                className="text-[12px] text-ink-mid border-l-2 border-ink/20 pl-2"
              >
                <span className="font-mono text-[11px] text-ink font-bold">
                  {c.title}
                </span>
                {c.text && (
                  <span className="ml-2 italic">"{c.text}"</span>
                )}
              </li>
            ))}
          </ul>
        </div>
      )}
      {entities.length > 0 && (
        <div>
          <div className="font-mono text-[10px] uppercase tracking-[0.22em] text-ink-mid mb-1.5">
            Sensitive entities
          </div>
          <div className="flex flex-wrap gap-1">
            {entities.slice(0, 12).map((e, i) => (
              <span
                key={i}
                className="font-mono text-[10px] px-1.5 py-0.5 bg-paper-deep border border-ink/25 text-ink"
              >
                {e}
              </span>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

function buildLesson(decision) {
  if (decision.verdict === "PERMIT") {
    return `You wrote content specific enough to stay below the forbid threshold and grounded enough to keep evidence sufficiency high. That's exactly the territory agents need to operate in.`;
  }
  if (decision.verdict === "ABSTAIN") {
    return `You landed in the uncertainty band. Evidence was weak or confidence dropped below the policy minimum, so Tex escalated for human review instead of blocking. In production that's a draw — work stops.`;
  }
  if (decision.deterministic?.findings?.length) {
    return `A deterministic recognizer caught you before the semantic judge even needed to run. Recognizers are cheap, fast, and boring — which is why they always fire first.`;
  }
  return `The semantic layer caught intent the keyword recognizers missed. This is the case LLM-as-judge was built for: content that's grammatically fine but substantively out-of-policy.`;
}
