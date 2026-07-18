import type { AnomalyFindingOut, LogEntryOut } from "@/lib/api";
import { formatHour } from "@/lib/format";
import { ACCENT, SEVERITY_HEX } from "@/lib/palette";
import { SEVERITY_ORDER } from "@/lib/severity";

interface SummaryTabProps {
  narrative: string | null;
  llmOk: boolean;
  findings: readonly AnomalyFindingOut[];
  /** Loaded entries, used to resolve each finding's time by entry id. */
  entries: readonly LogEntryOut[];
}

export function SummaryTab({ narrative, llmOk, findings, entries }: SummaryTabProps) {
  const events = buildTimeline(findings, entries);

  return (
    <div className="flex flex-col gap-5">
      <div>
        <p className="text-[12px] font-medium text-ink-muted">SOC timeline</p>
        <h1 className="mt-1 text-[20px] font-semibold text-ink-primary">
          Analyst summary
        </h1>
      </div>

      <section
        aria-labelledby="narrative-heading"
        className="rounded-[10px] border border-border bg-surface px-7 py-6"
        style={{ borderLeft: `3px solid ${ACCENT}` }}
      >
        <div className="flex flex-wrap items-center justify-between gap-2.5">
          <h2 id="narrative-heading" className="text-[12px] font-semibold text-ink-primary">
            Narrative
          </h2>
          <ProvenanceChip llmOk={llmOk} />
        </div>
        <p className="mt-4 max-w-[68ch] whitespace-pre-wrap text-[14px] leading-[1.8] text-ink-secondary">
          {narrative ?? "No narrative was produced for this upload."}
        </p>
      </section>

      <section aria-labelledby="events-heading">
        <p id="events-heading" className="mb-3.5 text-[12px] font-medium text-ink-muted">
          Event sequence
        </p>
        {events.length === 0 ? (
          <p className="text-[13px] text-ink-muted">No findings to sequence.</p>
        ) : (
          <ol>
            {events.map((event, i) => (
              <li key={i} className="flex gap-4">
                <div className="flex w-3 flex-none flex-col items-center">
                  <span
                    className="mt-1 h-2 w-2 flex-none rounded-full"
                    style={{ background: event.color }}
                    aria-hidden="true"
                  />
                  {i < events.length - 1 && <span className="w-px flex-1 bg-border" />}
                </div>
                <div className="pb-[22px]">
                  <p className="font-mono text-[12px] font-medium text-ink-faint">
                    {event.time}
                  </p>
                  <p className="mt-1 text-[13px] leading-relaxed text-ink-secondary">
                    {event.text}
                  </p>
                </div>
              </li>
            ))}
          </ol>
        )}
      </section>
    </div>
  );
}

interface TimelineEvent {
  time: string;
  color: string;
  text: string;
}

/** Prose over the findings, worst first. Time comes from the anchor entry when
 *  it is on the loaded page; otherwise it is left blank, matching the tooltip
 *  enrichment caveat. */
function buildTimeline(
  findings: readonly AnomalyFindingOut[],
  entries: readonly LogEntryOut[],
): TimelineEvent[] {
  const tsByEntry = new Map(entries.map((e) => [e.id, e.ts]));

  return [...findings]
    .sort(
      (a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity),
    )
    .map((finding) => {
      const ts = finding.entry_id !== null ? tsByEntry.get(finding.entry_id) : null;
      return {
        time: ts ? formatHour(ts) : "—",
        color: SEVERITY_HEX[finding.severity],
        text: finding.explanation
          ? `${finding.reason} — ${finding.explanation}`
          : finding.reason,
      };
    });
}

function ProvenanceChip({ llmOk }: { llmOk: boolean }) {
  const color = llmOk ? ACCENT : SEVERITY_HEX.high;
  return (
    <span
      className="inline-flex items-center gap-1.5 rounded-full border border-border px-3 py-1 text-[11px]"
      style={{ color }}
    >
      <span
        className="h-1.5 w-1.5 rounded-full"
        style={{ background: color }}
        aria-hidden="true"
      />
      {llmOk ? "written by Claude" : "deterministic fallback"}
    </span>
  );
}
