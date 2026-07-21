import { Card } from "@/components/ui/card";
import type { AnomalyFindingOut } from "@/lib/api";
import { formatHour } from "@/lib/format";
import { ACCENT, SEVERITY_HEX, SEVERITY_SOLID } from "@/lib/palette";
import { SEVERITY_ORDER } from "@/lib/severity";

interface SummaryTabProps {
  narrative: string | null;
  llmOk: boolean;
  findings: readonly AnomalyFindingOut[];
}

export function SummaryTab({ narrative, llmOk, findings }: SummaryTabProps) {
  const events = buildTimeline(findings);

  return (
    <div className="flex flex-col gap-5">
      <div>
        <p className="text-xs font-medium uppercase tracking-[0.06em] text-muted-foreground">
          SOC timeline
        </p>
        <h1 className="mt-1 text-xl font-semibold tracking-tight">Analyst summary</h1>
      </div>

      <Card
        aria-labelledby="narrative-heading"
        className="gap-0 px-7 py-6"
        style={{ boxShadow: `inset 3px 0 0 ${ACCENT}` }}
      >
        <div className="flex flex-wrap items-center justify-between gap-2.5">
          <h2 id="narrative-heading" className="text-xs font-semibold text-foreground">
            Narrative
          </h2>
          <ProvenanceChip llmOk={llmOk} />
        </div>
        <p className="mt-4 max-w-[68ch] whitespace-pre-wrap text-sm leading-[1.8] text-foreground/80">
          {narrative ?? "No narrative was produced for this upload."}
        </p>
      </Card>

      <section aria-labelledby="events-heading">
        <p id="events-heading" className="mb-3.5 text-xs font-medium uppercase tracking-[0.06em] text-muted-foreground">
          Event sequence
        </p>
        {events.length === 0 ? (
          <p className="text-[13px] text-muted-foreground">No findings to sequence.</p>
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
                  <p className="font-mono text-xs font-medium text-muted-foreground">
                    {event.time}
                  </p>
                  <p className="mt-1 text-[13px] leading-relaxed text-foreground/80">
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

/** Prose over the findings, worst first. Anchor time arrives with the finding,
 *  so entry-table pagination cannot erase chronology from the timeline. */
function buildTimeline(findings: readonly AnomalyFindingOut[]): TimelineEvent[] {
  return [...findings]
    .sort(
      (a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity),
    )
    .map((finding) => {
      return {
        time: finding.anchor_ts ? formatHour(finding.anchor_ts) : "—",
        color: SEVERITY_HEX[finding.severity],
        text: finding.explanation
          ? `${finding.reason} — ${finding.explanation}`
          : finding.reason,
      };
    });
}

function ProvenanceChip({ llmOk }: { llmOk: boolean }) {
  const color = llmOk ? ACCENT : SEVERITY_SOLID.high;
  return (
    <span
      className="inline-flex items-center gap-1.5 rounded-full px-3 py-1 text-[11px] font-medium text-white"
      style={{ background: color }}
    >
      <span className="h-1.5 w-1.5 rounded-full bg-white/80" aria-hidden="true" />
      {llmOk ? "written by Claude" : "deterministic fallback"}
    </span>
  );
}
