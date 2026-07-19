"use client";

import { useCallback, useEffect, useState } from "react";

import { Button } from "@/components/ui/button";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
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
          <p className="text-xs font-medium uppercase tracking-[0.06em] text-muted-foreground">
            Threat Intel
          </p>
          <h1 className="mt-1 text-xl font-semibold tracking-tight">
            VirusTotal reputation
          </h1>
        </div>
        {data?.enabled && (
          <div className="flex items-center gap-2">
            {hasResults && <ExportMenu uploadId={uploadId} />}
            <Button onClick={onEnrich} disabled={enriching}>
              {enriching
                ? "Enriching…"
                : hasResults
                  ? "Re-run VirusTotal"
                  : "Enrich with VirusTotal"}
            </Button>
          </div>
        )}
      </div>

      {error && (
        <p className="rounded-lg border border-error-border bg-error-bg px-3 py-2.5 text-xs text-error-text">
          {error}
        </p>
      )}

      {result && (
        <p className="rounded-lg border bg-card px-4 py-2.5 text-xs text-muted-foreground">
          Enriched <b className="font-mono text-foreground">{result.enriched}</b> of{" "}
          <b className="font-mono text-foreground">{result.indicators_seen}</b> indicators
          {" · "}
          <b className="font-mono text-foreground">{result.from_cache}</b> from cache
          {" · "}
          <b className="font-mono text-foreground">{result.alerts}</b> alert
          {result.alerts === 1 ? "" : "s"}
          {result.unavailable > 0 && (
            <>
              {" · "}
              <span className="text-muted-foreground">{result.unavailable} unreachable</span>
            </>
          )}
        </p>
      )}

      {loading ? (
        <p className="py-8 text-[13px] text-muted-foreground">Loading threat intel…</p>
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
    <div className="rounded-xl border border-dashed bg-card px-6 py-8 text-center">
      <p className="text-sm font-medium text-foreground">VirusTotal isn’t configured</p>
      <p className="mx-auto mt-1.5 max-w-[52ch] text-[13px] text-muted-foreground">
        Set <code className="font-mono text-foreground">VIRUSTOTAL_API_KEY</code> on the
        backend and restart it to enable destination reputation lookups and SIEM alert
        export.
      </p>
    </div>
  );
}

function EmptyState() {
  return (
    <div className="rounded-xl border border-dashed bg-card px-6 py-8 text-center">
      <p className="text-sm font-medium text-foreground">No enrichment yet</p>
      <p className="mx-auto mt-1.5 max-w-[52ch] text-[13px] text-muted-foreground">
        Run VirusTotal to fetch reputation, detections, and threat labels for this
        upload’s destination URLs, domains, and IPs. Malicious hits are raised as alerts
        and marked in the log.
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
      <span className="text-xs text-muted-foreground">SIEM export</span>
      <Button variant="outline" size="sm" onClick={() => download("json")} disabled={busy}>
        JSON
      </Button>
      <Button variant="outline" size="sm" onClick={() => download("cef")} disabled={busy}>
        CEF
      </Button>
    </div>
  );
}

const TYPE_LABEL: Record<string, string> = { ip: "IP", domain: "Domain", url: "URL" };

function VerdictTable({ enrichments }: { enrichments: IocEnrichmentOut[] }) {
  return (
    <div className="overflow-x-auto rounded-xl border bg-card">
      <Table className="text-xs">
        <TableHeader>
          <TableRow className="bg-muted/40 hover:bg-muted/40">
            <TableHead className="w-6" />
            <TableHead>Indicator</TableHead>
            <TableHead>Type</TableHead>
            <TableHead className="text-right">Malicious</TableHead>
            <TableHead className="text-right">Suspicious</TableHead>
            <TableHead className="text-right">Harmless</TableHead>
            <TableHead className="text-right">Reputation</TableHead>
            <TableHead>Threat labels</TableHead>
            <TableHead />
          </TableRow>
        </TableHeader>
        <TableBody>
          {enrichments.map((row) => (
            <VerdictRow key={row.id} row={row} />
          ))}
        </TableBody>
      </Table>
    </div>
  );
}

function VerdictRow({ row }: { row: IocEnrichmentOut }) {
  const severity = severityFor(row);
  const flagged = severity !== null;
  const unreachable = row.status === "unavailable";

  return (
    <TableRow className={flagged ? "bg-destructive/[0.05] hover:bg-destructive/[0.08]" : undefined}>
      <TableCell>
        {flagged && (
          <span
            className="block h-1.5 w-1.5 rounded-full"
            style={{ background: SEVERITY_HEX[severity] }}
          >
            <span className="sr-only">{severity} reputation</span>
          </span>
        )}
      </TableCell>
      <TableCell className="max-w-[320px] truncate font-mono text-foreground" title={row.indicator}>
        {row.indicator}
      </TableCell>
      <TableCell>
        <span className="rounded border px-1.5 py-px text-[10px] font-medium uppercase tracking-[0.04em] text-muted-foreground">
          {TYPE_LABEL[row.indicator_type] ?? row.indicator_type}
        </span>
      </TableCell>
      {unreachable ? (
        <TableCell colSpan={4} className="text-muted-foreground">
          unreachable — VirusTotal did not respond
        </TableCell>
      ) : (
        <>
          <Num value={row.malicious} tone={row.malicious > 0 ? "danger" : "muted"} />
          <Num value={row.suspicious} tone={row.suspicious > 0 ? "warn" : "muted"} />
          <Num value={row.harmless} tone="muted" />
          <Num value={row.reputation} tone="muted" />
        </>
      )}
      <TableCell>
        {row.threat_labels.length > 0 ? (
          <span className="flex flex-wrap gap-1">
            {row.threat_labels.slice(0, 3).map((label) => (
              <span
                key={label}
                className="rounded bg-muted px-1.5 py-px font-mono text-[11px] text-foreground/80"
              >
                {label}
              </span>
            ))}
          </span>
        ) : (
          <span className="text-muted-foreground">—</span>
        )}
      </TableCell>
      <TableCell className="text-right">
        {row.vt_link && (
          <a
            href={row.vt_link}
            target="_blank"
            rel="noopener noreferrer"
            className="text-xs font-medium text-accent hover:underline"
          >
            VT ↗
          </a>
        )}
      </TableCell>
    </TableRow>
  );
}

const TONE: Record<string, string> = {
  danger: "text-danger font-semibold",
  warn: "text-sev-medium font-semibold",
  muted: "text-muted-foreground",
};

function Num({ value, tone }: { value: number; tone: "danger" | "warn" | "muted" }) {
  return (
    <TableCell className={`text-right font-mono tabular-nums ${TONE[tone]}`}>
      {value}
    </TableCell>
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
