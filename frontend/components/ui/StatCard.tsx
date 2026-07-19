import type { ReactNode } from "react";

type Tone = "neutral" | "danger" | "accent";

// A hairline top rule tints the card by meaning — a flagged-count card reads
// "danger" at a glance without shouting. Neutral cards keep the plain surface.
const TOP_RULE: Record<Tone, string> = {
  neutral: "before:bg-border",
  danger: "before:bg-sev-critical",
  accent: "before:bg-accent",
};

interface StatCardProps {
  label: string;
  /** Right-aligned caption in the header row (e.g. "7.1% of traffic"). */
  aside?: string;
  tone?: Tone;
  /** The headline value. Omit when passing custom `children` (e.g. a meter). */
  value?: ReactNode;
  /** Sub-caption under the value. */
  hint?: string;
  children?: ReactNode;
}

/** Bento stat tile: an uppercase label, a big mono value, an optional tinted
 *  top rule. Ported from the Tremor KPI-card pattern, restyled onto our tokens
 *  so it stays inside the light SecOps system. */
export function StatCard({
  label,
  aside,
  tone = "neutral",
  value,
  hint,
  children,
}: StatCardProps) {
  return (
    <div
      className={`relative rounded-xl border border-border bg-surface px-[18px] py-4 shadow-card before:absolute before:inset-x-0 before:top-0 before:h-[3px] before:rounded-t-xl before:content-[''] ${TOP_RULE[tone]}`}
    >
      <div className="flex items-baseline justify-between gap-2">
        <p className="text-[11px] font-semibold uppercase tracking-[0.06em] text-ink-muted">
          {label}
        </p>
        {aside && <p className="font-mono text-[12px] text-ink-faint">{aside}</p>}
      </div>

      {value !== undefined && (
        <p className="mt-2 font-mono text-[30px] font-semibold leading-none text-ink-primary">
          {value}
        </p>
      )}
      {hint && <p className="mt-1.5 font-mono text-[12px] text-ink-faint">{hint}</p>}
      {children}
    </div>
  );
}
