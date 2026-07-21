"use client";

import { useLayoutEffect, useMemo, useRef, useState } from "react";

import { AnchorFinding } from "@/components/results/AnchorFinding";
import { EntriesSearch } from "@/components/results/EntriesSearch";
import { EntriesTable } from "@/components/results/EntriesTable";
import { StatCard } from "@/components/ui/StatCard";
import type { AnomalyFindingOut, LogEntryOut, Severity, UploadOut } from "@/lib/api";
import { detectorLabel, formatNumber, formatTimestamp } from "@/lib/format";
import { SEVERITY_HEX } from "@/lib/palette";
import { findingsWorstFirst, severityMix } from "@/lib/severity";

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
  /** Active search term (from the URL), and the handler that rewrites it. */
  query: string;
  onSearch: (q: string) => void;
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
  query,
  onSearch,
  entriesLoading,
  onPageChange,
  loadError,
}: OverviewTabProps) {
  const failed = upload.status.toLowerCase() === "failed";
  const flaggedShare = totalEntries > 0 ? ((flaggedCount / totalEntries) * 100).toFixed(1) : "0.0";

  // The one finding to open first, and the log row it points at when that row is
  // on the loaded page (the anchor may sit on a later page — then we lead with
  // the finding alone).
  const topFinding = useMemo(() => findingsWorstFirst(findings)[0] ?? null, [findings]);
  const anchorEntry = useMemo(
    () => (topFinding ? (entries.find((e) => e.id === topFinding.entry_id) ?? null) : null),
    [topFinding, entries],
  );

  return (
    <div className="flex flex-col gap-5">
      <div className="flex flex-wrap items-center gap-3">
        <h1 className="font-mono text-[20px] font-semibold text-ink-primary">
          {upload.filename}
        </h1>
        <span
          className={`rounded-md border bg-surface px-2.5 py-[3px] text-[11px] font-medium ${failed ? "text-danger" : "text-success"}`}
        >
          {capitalize(upload.status)}
        </span>
        <span className="font-mono text-[12px] text-ink-faint">
          uploaded {formatTimestamp(upload.created_at)}
        </span>
      </div>

      {loadError && (
        <p className="rounded-lg border border-error-border bg-error-bg px-3 py-2.5 text-[12px] text-error-text">
          {loadError}
        </p>
      )}

      <AnchorFinding
        finding={topFinding}
        entry={anchorEntry}
        uploadId={upload.id}
        totalFindings={findings.length}
      />

      <div className="grid gap-3.5 grid-cols-1 md:grid-cols-[1fr_1fr_1.6fr]">
        <StatCard label="Entries parsed" value={formatNumber(totalEntries)} />

        <StatCard
          label="Entries flagged"
          tone={flaggedCount > 0 ? "danger" : "neutral"}
          value={
            <span className={flaggedCount > 0 ? "text-sev-critical" : undefined}>
              {formatNumber(flaggedCount)}
            </span>
          }
          hint={`${flaggedShare}% of traffic`}
        />

        <StatCard
          label="Findings by severity"
          aside={
            findings.length > 0
              ? `${findings.length} across ${formatNumber(flaggedCount)} ${flaggedCount === 1 ? "entry" : "entries"}`
              : undefined
          }
        >
          <SeverityBar findings={findings} />
        </StatCard>
      </div>

      <div>
        <EntriesSearch
          value={query}
          onSearch={onSearch}
          resultCount={tableTotal}
          loading={entriesLoading}
        />
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
  const popoverRef = useRef<HTMLSpanElement>(null);
  const [below, setBelow] = useState(false);
  const color = SEVERITY_HEX[severity];
  const items = findings
    .filter((f) => f.severity === severity)
    .map((f) => `${detectorLabel(f.type)} — ${f.reason}`);

  useLayoutEffect(() => {
    const popover = popoverRef.current;
    const anchor = popover?.parentElement;
    if (!popover || !anchor) return;

    const anchorTop = anchor.getBoundingClientRect().top;
    const popoverHeight = popover.getBoundingClientRect().height;
    setBelow(anchorTop - popoverHeight - 10 < 8);
  }, [count, severity]);

  return (
    <span
      ref={popoverRef}
      className={`pointer-events-none absolute left-1/2 z-30 flex max-h-[420px] w-[250px] -translate-x-1/2 flex-col gap-1.5 overflow-y-auto rounded-lg border border-border bg-surface p-3 shadow-popover ${
        below ? "top-[calc(100%+10px)]" : "bottom-[calc(100%+10px)]"
      }`}
      style={{ borderTop: `2px solid ${color}` }}
    >
      <span
        className="text-[10px] font-semibold capitalize tracking-[0.04em]"
        style={{ color }}
      >
        {severity} · {count} findings
      </span>
      {items.map((item, i) => (
        <span key={i} className="text-[11px] leading-relaxed text-ink-secondary">
          • {item}
        </span>
      ))}
    </span>
  );
}

function capitalize(s: string): string {
  return s ? s.charAt(0).toUpperCase() + s.slice(1) : "—";
}
