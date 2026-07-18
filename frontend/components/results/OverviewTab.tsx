"use client";

import Link from "next/link";
import { useState } from "react";

import { EntriesTable } from "@/components/results/EntriesTable";
import type { AnomalyFindingOut, LogEntryOut, Severity, UploadOut } from "@/lib/api";
import { detectorLabel, formatNumber, formatTimestamp } from "@/lib/format";
import { SEVERITY_HEX, SUCCESS, DANGER } from "@/lib/palette";
import { severityMix } from "@/lib/severity";

interface OverviewTabProps {
  upload: UploadOut;
  totalEntries: number;
  flaggedCount: number;
  findings: readonly AnomalyFindingOut[];
  entries: readonly LogEntryOut[];
  flagged: ReadonlyMap<number, Severity>;
  page: number;
  pageSize: number;
  tableTotal: number;
  entriesLoading: boolean;
  onPageChange: (page: number) => void;
  loadError: string | null;
}

export function OverviewTab({
  upload,
  totalEntries,
  flaggedCount,
  findings,
  entries,
  flagged,
  page,
  pageSize,
  tableTotal,
  entriesLoading,
  onPageChange,
  loadError,
}: OverviewTabProps) {
  const failed = upload.status.toLowerCase() === "failed";
  const flaggedShare = totalEntries > 0 ? ((flaggedCount / totalEntries) * 100).toFixed(1) : "0.0";

  return (
    <div className="flex flex-col gap-5">
      <div className="flex flex-wrap items-center gap-3">
        <h1 className="font-mono text-[20px] font-semibold text-ink-primary">
          {upload.filename}
        </h1>
        <span
          className="rounded-md border border-border bg-surface px-2.5 py-[3px] text-[11px] font-medium"
          style={{ color: failed ? DANGER : SUCCESS }}
        >
          {capitalize(upload.status)}
        </span>
        <span className="font-mono text-[12px] text-ink-faint">
          uploaded {formatTimestamp(upload.created_at)}
        </span>
        <Link
          href="/upload"
          className="ml-auto rounded-md border border-border-strong bg-surface px-3 py-[7px] text-[12px] font-medium text-ink-secondary transition-colors hover:border-ink-faint hover:bg-surface-alt"
        >
          New upload
        </Link>
      </div>

      {loadError && (
        <p className="rounded-lg border border-error-border bg-error-bg px-3 py-2.5 text-[12px] text-error-text">
          {loadError}
        </p>
      )}

      <div className="grid gap-3.5 grid-cols-1 md:grid-cols-[1fr_1fr_1.5fr]">
        <Tile label="Entries parsed">
          <p className="mt-2 font-mono text-[28px] font-semibold text-ink-primary">
            {formatNumber(totalEntries)}
          </p>
        </Tile>

        <Tile label="Entries flagged">
          <p className="mt-2 font-mono text-[28px] font-semibold text-sev-critical">
            {formatNumber(flaggedCount)}
          </p>
          <p className="mt-1 font-mono text-[12px] text-ink-faint">
            {flaggedShare}% of traffic
          </p>
        </Tile>

        <Tile
          label="Findings by severity"
          aside={
            findings.length > 0
              ? `${findings.length} across ${formatNumber(flaggedCount)} ${flaggedCount === 1 ? "entry" : "entries"}`
              : undefined
          }
        >
          <SeverityBar findings={findings} />
        </Tile>
      </div>

      <EntriesTable
        entries={entries}
        flagged={flagged}
        page={page}
        pageSize={pageSize}
        totalEntries={tableTotal}
        loading={entriesLoading}
        onPageChange={onPageChange}
      />
    </div>
  );
}

function Tile({
  label,
  aside,
  children,
}: {
  label: string;
  aside?: string;
  children: React.ReactNode;
}) {
  return (
    <div className="rounded-[10px] border border-border bg-surface px-[18px] py-4">
      <div className="flex items-baseline justify-between gap-2">
        <p className="text-[12px] font-medium text-ink-muted">{label}</p>
        {aside && <p className="font-mono text-[12px] text-ink-faint">{aside}</p>}
      </div>
      {children}
    </div>
  );
}

/** The stacked severity bar: segments size by count, and hovering one pops a
 *  popover of that severity's findings. Counts carry the meaning; the bar only
 *  makes the proportion glanceable. */
function SeverityBar({ findings }: { findings: readonly AnomalyFindingOut[] }) {
  const [hover, setHover] = useState<Severity | null>(null);
  const bands = severityMix(findings).filter((band) => band.count > 0);

  if (bands.length === 0) {
    return <p className="mt-3 text-[13px] text-ink-muted">No anomalies detected.</p>;
  }

  return (
    <>
      <div className="mt-3 flex h-2 gap-0.5">
        {bands.map((band) => (
          <span
            key={band.severity}
            onMouseEnter={() => setHover(band.severity)}
            onMouseLeave={() => setHover(null)}
            className="relative cursor-default rounded-[2px]"
            style={{ flexGrow: band.count, background: SEVERITY_HEX[band.severity] }}
          >
            {hover === band.severity && (
              <SeverityPopover severity={band.severity} count={band.count} findings={findings} />
            )}
          </span>
        ))}
      </div>

      <dl className="mt-2.5 flex flex-wrap gap-x-3.5 gap-y-1.5">
        {bands.map((band) => (
          <div key={band.severity} className="flex items-center gap-1.5 text-[12px]">
            <span
              className="h-2 w-2 rounded-[2px]"
              style={{ background: SEVERITY_HEX[band.severity] }}
              aria-hidden="true"
            />
            <dt className="capitalize text-ink-muted">{band.severity}</dt>
            <dd className="font-mono font-semibold text-ink-primary">{band.count}</dd>
          </div>
        ))}
      </dl>
    </>
  );
}

function SeverityPopover({
  severity,
  count,
  findings,
}: {
  severity: Severity;
  count: number;
  findings: readonly AnomalyFindingOut[];
}) {
  const color = SEVERITY_HEX[severity];
  const items = findings
    .filter((f) => f.severity === severity)
    .map((f) => `${detectorLabel(f.type)} — ${f.reason}`);

  return (
    <span
      className="pointer-events-none absolute bottom-[calc(100%+10px)] left-1/2 z-30 flex w-[250px] -translate-x-1/2 flex-col gap-1.5 rounded-lg border border-border bg-surface p-3 shadow-popover"
      style={{ borderTop: `2px solid ${color}` }}
    >
      <span
        className="text-[10px] font-semibold capitalize tracking-[0.04em]"
        style={{ color }}
      >
        {severity} · {count} findings
      </span>
      {items.map((item, i) => (
        <span key={i} className="text-[11px] leading-relaxed text-[#475467]">
          • {item}
        </span>
      ))}
    </span>
  );
}

function capitalize(s: string): string {
  return s ? s.charAt(0).toUpperCase() + s.slice(1) : "—";
}
