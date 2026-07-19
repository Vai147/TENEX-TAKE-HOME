import Link from "next/link";

import type { AnomalyFindingOut, LogEntryOut } from "@/lib/api";
import { detectorLabel } from "@/lib/format";
import { SEVERITY_HEX, SEVERITY_SOLID, SUCCESS } from "@/lib/palette";

interface AnchorFindingProps {
  /** The worst finding, or null when the file is clean. */
  finding: AnomalyFindingOut | null;
  /** The log row the finding anchors to, when it is on the loaded page. */
  entry: LogEntryOut | null;
  uploadId: number;
  totalFindings: number;
}

/** The headline band: the single finding an analyst should open first, given
 *  the width and colour it deserves. A clean file gets a calm green state so the
 *  page still leads with a verdict instead of dead space. */
export function AnchorFinding({
  finding,
  entry,
  uploadId,
  totalFindings,
}: AnchorFindingProps) {
  if (!finding) return <CleanState />;

  const accent = SEVERITY_HEX[finding.severity];
  const others = totalFindings - 1;

  return (
    <section
      className="relative overflow-hidden rounded-xl border border-border bg-surface shadow-card"
      style={{ boxShadow: `inset 4px 0 0 ${accent}, 0 1px 3px rgba(16,24,40,0.06)` }}
    >
      {/* A faint wash of the severity colour bleeds from the rail so the band
          reads as urgent without a heavy fill. */}
      <div
        aria-hidden="true"
        className="pointer-events-none absolute inset-0"
        style={{ background: `linear-gradient(90deg, ${accent}0f, transparent 42%)` }}
      />

      <div className="relative flex flex-col gap-3.5 px-6 py-5">
        <div className="flex flex-wrap items-center gap-2.5">
          <span className="text-[11px] font-semibold uppercase tracking-[0.08em] text-ink-faint">
            Top finding
          </span>
          <span
            className="rounded-md px-2 py-[2px] text-[10px] font-semibold uppercase tracking-[0.04em] text-white"
            style={{ background: SEVERITY_SOLID[finding.severity] }}
          >
            {finding.severity}
          </span>
          {finding.technique_id && (
            <span className="rounded-md border border-border bg-surface-alt px-2 py-[2px] font-mono text-[10px] text-ink-muted">
              ATT&CK {finding.technique_id}
            </span>
          )}
          <span className="ml-auto flex items-center gap-2 font-mono text-[12px] text-ink-muted">
            <ConfidenceMeter value={finding.confidence} accent={accent} />
            {Math.round(finding.confidence * 100)}% confidence
          </span>
        </div>

        <div>
          <h2 className="text-[19px] font-semibold text-ink-primary">
            {detectorLabel(finding.type)}
          </h2>
          <p className="mt-1 text-[13px] leading-relaxed text-ink-secondary">
            {finding.reason}
          </p>
        </div>

        {entry && <EntryStrip entry={entry} />}

        <div className="flex flex-wrap items-center gap-x-4 gap-y-1">
          <Link
            href={`/uploads/${uploadId}/alerts`}
            className="text-[12px] font-semibold text-accent transition-colors hover:text-accent-hover"
          >
            Investigate in Alerts →
          </Link>
          {others > 0 && (
            <span className="text-[12px] text-ink-faint">
              +{others} more finding{others === 1 ? "" : "s"}
            </span>
          )}
        </div>
      </div>
    </section>
  );
}

/** The offending row, mono and compact, so the analyst sees who/where without
 *  leaving the headline. */
function EntryStrip({ entry }: { entry: LogEntryOut }) {
  const blocked = (entry.action ?? "").toLowerCase() === "blocked";
  return (
    <div className="flex flex-wrap items-center gap-x-3 gap-y-1 rounded-lg border border-border bg-surface-alt px-3 py-2 font-mono text-[12px]">
      {entry.src_ip && <span className="text-ink-primary">{entry.src_ip}</span>}
      {entry.user && (
        <>
          <span className="text-ink-disabled">·</span>
          <span className="text-ink-secondary">{entry.user}</span>
        </>
      )}
      {entry.url && (
        <>
          <span className="text-ink-disabled">·</span>
          <span className="max-w-[46ch] truncate text-ink-muted" title={entry.url}>
            {entry.url}
          </span>
        </>
      )}
      {entry.action && (
        <span className={`ml-auto font-semibold ${blocked ? "text-danger" : "text-success"}`}>
          {entry.action}
          {entry.status_code != null && (
            <span className="text-ink-faint"> · {entry.status_code}</span>
          )}
        </span>
      )}
    </div>
  );
}

function ConfidenceMeter({ value, accent }: { value: number; accent: string }) {
  const pct = Math.max(0, Math.min(1, value)) * 100;
  return (
    <span
      className="inline-block h-1.5 w-16 overflow-hidden rounded-full bg-divider"
      aria-hidden="true"
    >
      <span
        className="block h-full rounded-full"
        style={{ width: `${pct}%`, background: accent }}
      />
    </span>
  );
}

function CleanState() {
  return (
    <section
      className="relative overflow-hidden rounded-xl border border-border bg-surface px-6 py-5 shadow-card"
      style={{ boxShadow: `inset 4px 0 0 ${SUCCESS}, 0 1px 3px rgba(16,24,40,0.06)` }}
    >
      <span className="text-[11px] font-semibold uppercase tracking-[0.08em] text-ink-faint">
        Verdict
      </span>
      <h2 className="mt-1 text-[19px] font-semibold text-ink-primary">
        No anomalies detected
      </h2>
      <p className="mt-1 text-[13px] text-ink-secondary">
        Nothing in this file crossed a detector threshold.
      </p>
    </section>
  );
}
