"use client";

import { useCallback, useEffect, useState } from "react";

import {
  fetchAlertsExport,
  getThreatIntel,
  runEnrichment,
  type EnrichResultOut,
  type IocEnrichmentOut,
  type ThreatIntelOut,
} from "@/lib/api";
import { SEVERITY_HEX } from "@/lib/palette";

interface ThreatIntelTabProps {
  uploadId: number;
}

export function ThreatIntelTab({ uploadId }: ThreatIntelTabProps) {
  const [data, setData] = useState<ThreatIntelOut | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [enriching, setEnriching] = useState(false);
  const [result, setResult] = useState<EnrichResultOut | null>(null);

  const load = useCallback(async () => {
    setError(null);
    try {
      setData(await getThreatIntel(uploadId));
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load threat intel");
    } finally {
      setLoading(false);
    }
  }, [uploadId]);

  useEffect(() => {
    load();
  }, [load]);

  async function onEnrich() {
    setEnriching(true);
    setError(null);
    try {
      const res = await runEnrichment(uploadId);
      setResult(res);
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Enrichment failed");
    } finally {
      setEnriching(false);
    }
  }

  const enrichments = data?.enrichments ?? [];
  const hasResults = enrichments.length > 0;

  return (
    <div className="flex flex-col gap-5">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <p className="text-[12px] font-medium text-ink-muted">Threat Intel</p>
          <h1 className="mt-1 text-[20px] font-semibold text-ink-primary">
            VirusTotal reputation
          </h1>
        </div>
        {data?.enabled && (
          <div className="flex items-center gap-2">
            {hasResults && <ExportMenu uploadId={uploadId} />}
            <button
              type="button"
              onClick={onEnrich}
              disabled={enriching}
              className="rounded-lg bg-accent px-4 py-2 text-[13px] font-semibold text-white transition-colors hover:bg-accent-hover disabled:opacity-60"
            >
              {enriching
                ? "Enriching…"
                : hasResults
                  ? "Re-run VirusTotal"
                  : "Enrich with VirusTotal"}
            </button>
          </div>
        )}
      </div>

      {error && (
        <p className="rounded-lg border border-error-border bg-error-bg px-3 py-2.5 text-[12px] text-error-text">
          {error}
        </p>
      )}

      {result && (
        <p className="rounded-lg border border-border bg-surface px-4 py-2.5 text-[12px] text-ink-secondary">
          Enriched <b className="font-mono text-ink-primary">{result.enriched}</b> of{" "}
          <b className="font-mono text-ink-primary">{result.indicators_seen}</b> indicators
          {" · "}
          <b className="font-mono text-ink-primary">{result.from_cache}</b> from cache
          {" · "}
          <b className="font-mono text-ink-primary">{result.alerts}</b> alert
          {result.alerts === 1 ? "" : "s"}
          {result.unavailable > 0 && (
            <>
              {" · "}
              <span className="text-ink-muted">
                {result.unavailable} unreachable
              </span>
            </>
          )}
        </p>
      )}

      {loading ? (
        <p className="py-8 text-[13px] text-ink-muted">Loading threat intel…</p>
      ) : !data?.enabled ? (
        <NotConfigured />
      ) : !hasResults ? (
        <EmptyState />
      ) : (
        <VerdictTable enrichments={enrichments} />
      )}
    </div>
  );
}

function NotConfigured() {
  return (
    <div className="rounded-[10px] border border-dashed border-border bg-surface px-6 py-8 text-center">
      <p className="text-[14px] font-medium text-ink-primary">
        VirusTotal isn’t configured
      </p>
      <p className="mx-auto mt-1.5 max-w-[52ch] text-[13px] text-ink-muted">
        Set <code className="font-mono text-ink-secondary">VIRUSTOTAL_API_KEY</code> on
        the backend and restart it to enable destination reputation lookups and SIEM
        alert export.
      </p>
    </div>
  );
}

function EmptyState() {
  return (
    <div className="rounded-[10px] border border-dashed border-border bg-surface px-6 py-8 text-center">
      <p className="text-[14px] font-medium text-ink-primary">No enrichment yet</p>
      <p className="mx-auto mt-1.5 max-w-[52ch] text-[13px] text-ink-muted">
        Run VirusTotal to fetch reputation, detections, and threat labels for this
        upload’s destination URLs, domains, and IPs. Malicious hits are raised as
        alerts and marked in the log.
      </p>
    </div>
  );
}

function ExportMenu({ uploadId }: { uploadId: number }) {
  const [busy, setBusy] = useState(false);

  async function download(format: "json" | "cef") {
    setBusy(true);
    try {
      const text = await fetchAlertsExport(uploadId, format);
      const blob = new Blob([text], {
        type: format === "json" ? "application/json" : "text/plain",
      });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `alerts-${uploadId}.${format === "json" ? "json" : "cef"}`;
      a.click();
      URL.revokeObjectURL(url);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="flex items-center gap-1.5">
      <span className="text-[12px] text-ink-faint">SIEM export</span>
      <ExportButton onClick={() => download("json")} disabled={busy}>
        JSON
      </ExportButton>
      <ExportButton onClick={() => download("cef")} disabled={busy}>
        CEF
      </ExportButton>
    </div>
  );
}

function ExportButton({
  children,
  onClick,
  disabled,
}: {
  children: React.ReactNode;
  onClick: () => void;
  disabled: boolean;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      disabled={disabled}
      className="rounded-md border border-border-strong bg-surface px-2.5 py-1.5 text-[12px] font-medium text-ink-secondary transition-colors hover:border-ink-faint hover:bg-surface-alt disabled:opacity-50"
    >
      {children}
    </button>
  );
}

const TYPE_LABEL: Record<string, string> = { ip: "IP", domain: "Domain", url: "URL" };

function VerdictTable({ enrichments }: { enrichments: IocEnrichmentOut[] }) {
  return (
    <div className="overflow-x-auto rounded-[10px] border border-border bg-surface">
      <table className="w-full border-collapse text-[12px]">
        <thead>
          <tr className="bg-surface-alt text-left text-ink-muted">
            <th className="w-6 px-3.5 py-[11px]" />
            <Th>Indicator</Th>
            <Th>Type</Th>
            <Th className="text-right">Malicious</Th>
            <Th className="text-right">Suspicious</Th>
            <Th className="text-right">Harmless</Th>
            <Th className="text-right">Reputation</Th>
            <Th>Threat labels</Th>
            <Th />
          </tr>
        </thead>
        <tbody>
          {enrichments.map((row) => (
            <VerdictRow key={row.id} row={row} />
          ))}
        </tbody>
      </table>
    </div>
  );
}

function VerdictRow({ row }: { row: IocEnrichmentOut }) {
  const severity = severityFor(row);
  const flagged = severity !== null;
  const unreachable = row.status === "unavailable";

  return (
    <tr
      className="border-t border-divider align-middle"
      style={flagged ? { background: "rgba(217,45,32,0.05)" } : undefined}
    >
      <td className="px-3.5 py-2.5">
        {flagged && (
          <span
            className="block h-1.5 w-1.5 rounded-full"
            style={{ background: SEVERITY_HEX[severity] }}
          >
            <span className="sr-only">{severity} reputation</span>
          </span>
        )}
      </td>
      <td className="max-w-[320px] truncate px-3.5 py-2.5 font-mono text-ink-primary" title={row.indicator}>
        {row.indicator}
      </td>
      <td className="px-3.5 py-2.5">
        <span className="rounded border border-border px-1.5 py-px text-[10px] font-medium uppercase tracking-[0.04em] text-ink-muted">
          {TYPE_LABEL[row.indicator_type] ?? row.indicator_type}
        </span>
      </td>
      {unreachable ? (
        <td colSpan={4} className="px-3.5 py-2.5 text-ink-faint">
          unreachable — VirusTotal did not respond
        </td>
      ) : (
        <>
          <Num value={row.malicious} tone={row.malicious > 0 ? "danger" : "muted"} />
          <Num value={row.suspicious} tone={row.suspicious > 0 ? "warn" : "muted"} />
          <Num value={row.harmless} tone="muted" />
          <Num value={row.reputation} tone="muted" />
        </>
      )}
      <td className="px-3.5 py-2.5">
        {row.threat_labels.length > 0 ? (
          <span className="flex flex-wrap gap-1">
            {row.threat_labels.slice(0, 3).map((label) => (
              <span
                key={label}
                className="rounded bg-surface-alt px-1.5 py-px font-mono text-[11px] text-ink-secondary"
              >
                {label}
              </span>
            ))}
          </span>
        ) : (
          <span className="text-ink-faint">—</span>
        )}
      </td>
      <td className="px-3.5 py-2.5 text-right">
        {row.vt_link && (
          <a
            href={row.vt_link}
            target="_blank"
            rel="noopener noreferrer"
            className="text-[12px] font-medium text-accent hover:underline"
          >
            VT ↗
          </a>
        )}
      </td>
    </tr>
  );
}

function Th({ children, className = "" }: { children?: React.ReactNode; className?: string }) {
  return <th className={`px-3.5 py-[11px] font-medium ${className}`}>{children}</th>;
}

const TONE: Record<string, string> = {
  danger: "text-danger font-semibold",
  warn: "text-sev-medium font-semibold",
  muted: "text-ink-secondary",
};

function Num({ value, tone }: { value: number; tone: "danger" | "warn" | "muted" }) {
  return (
    <td className={`px-3.5 py-2.5 text-right font-mono tabular-nums ${TONE[tone]}`}>
      {value}
    </td>
  );
}

/** Row severity from VirusTotal detections, mirroring the backend bands. Returns
 *  null for a clean/unknown indicator (no marker). */
function severityFor(row: IocEnrichmentOut): keyof typeof SEVERITY_HEX | null {
  if (row.status !== "ok") return null;
  if (row.malicious >= 5) return "critical";
  if (row.malicious >= 3) return "high";
  if (row.malicious >= 1) return "medium";
  if (row.suspicious >= 1) return "low";
  return null;
}
