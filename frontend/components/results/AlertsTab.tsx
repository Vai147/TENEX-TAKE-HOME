import { Card } from "@/components/ui/card";
import type { AnomalyFindingOut } from "@/lib/api";
import { detectorLabel } from "@/lib/format";
import { SEVERITY_HEX, SEVERITY_SOLID } from "@/lib/palette";
import { SEVERITY_ORDER } from "@/lib/severity";

interface AlertsTabProps {
  findings: readonly AnomalyFindingOut[];
}

export function AlertsTab({ findings }: AlertsTabProps) {
  // Worst severity first, then most-confident within a severity: the order an
  // analyst works the queue in.
  const ordered = [...findings].sort(
    (a, b) =>
      SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity) ||
      b.confidence - a.confidence,
  );

  return (
    <div className="flex flex-col gap-5">
      <div className="flex flex-wrap items-baseline justify-between gap-2.5">
        <div>
          <p className="text-xs font-medium uppercase tracking-[0.06em] text-muted-foreground">
            Alerts
          </p>
          <h1 className="mt-1 text-xl font-semibold tracking-tight">Anomalies</h1>
        </div>
        <p className="text-xs text-muted-foreground">
          {findings.length === 0
            ? "Nothing flagged"
            : `${findings.length} finding${findings.length === 1 ? "" : "s"}, ranked by detector confidence`}
        </p>
      </div>

      {ordered.length === 0 ? (
        <p className="rounded-xl border border-dashed bg-card px-5 py-8 text-center text-[13px] text-muted-foreground">
          The rules engine found nothing anomalous in this file.
        </p>
      ) : (
        <div className="flex flex-col gap-3">
          {ordered.map((finding) => (
            <FindingCard key={finding.id} finding={finding} />
          ))}
        </div>
      )}
    </div>
  );
}

function FindingCard({ finding }: { finding: AnomalyFindingOut }) {
  const color = SEVERITY_HEX[finding.severity];
  const percent = Math.round(finding.confidence * 100);

  return (
    <Card
      className="gap-0 px-5 py-4 transition-colors hover:border-border-strong"
      style={{ boxShadow: `inset 3px 0 0 ${color}` }}
    >
      <div className="flex flex-wrap items-center gap-2.5">
        <h3 className="text-sm font-semibold text-foreground">
          {detectorLabel(finding.type)}
        </h3>
        <span
          className="rounded-md px-2 py-px text-[10px] font-semibold uppercase tracking-[0.04em] text-white"
          style={{ background: SEVERITY_SOLID[finding.severity] }}
        >
          {finding.severity}
        </span>
        <span className="ml-auto inline-flex items-center gap-1.5 text-[11px] text-muted-foreground">
          <span className="inline-block h-1 w-9 overflow-hidden rounded-[2px] bg-divider">
            <span className="block h-full" style={{ width: `${percent}%`, background: color }} />
          </span>
          {percent}% confidence
        </span>
      </div>

      <p className="mt-2.5 text-xs leading-[1.7] text-muted-foreground">{finding.reason}</p>

      {finding.explanation && (
        <div className="mt-3 border-l-2 pl-3">
          <p className="text-[10px] font-semibold tracking-[0.04em] text-accent">Claude</p>
          <p className="mt-1.5 text-[13px] leading-[1.7] text-foreground/80">
            {finding.explanation}
          </p>
        </div>
      )}
    </Card>
  );
}
