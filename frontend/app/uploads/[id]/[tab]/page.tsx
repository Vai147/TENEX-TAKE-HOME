"use client";

import dynamic from "next/dynamic";
import Link from "next/link";
import { useParams, useRouter, useSearchParams } from "next/navigation";
import { Suspense, useCallback, useEffect, useMemo, useState } from "react";

import { AskClaude } from "@/components/chat/AskClaude";
import { ConsoleHeader } from "@/components/layout/ConsoleHeader";
import { AlertsTab } from "@/components/results/AlertsTab";
import { CoverageTab } from "@/components/results/CoverageTab";
import { OverviewTab } from "@/components/results/OverviewTab";
import { SummaryTab } from "@/components/results/SummaryTab";
import { ThreatIntelTab } from "@/components/results/ThreatIntelTab";
import {
  getAnomalies,
  getToken,
  getUpload,
  type AnomaliesOut,
  type ChatContext,
  type UploadDetail,
} from "@/lib/api";
import { DEFAULT_TAB, isResultTab, tabFromParam, type ResultTab } from "@/lib/tabs";
import { worstSeverityByEntry } from "@/lib/severity";

// Recharts is the heaviest thing on the page and only the Dashboard tab needs
// it, so it stays out of the initial bundle.
const DashboardTab = dynamic(
  () => import("@/components/results/DashboardTab").then((m) => m.DashboardTab),
  { ssr: false, loading: () => <TabPlaceholder /> },
);

const PAGE_SIZE = 100;

// Overview/Dashboard run wide; Summary/Alerts are a reading column. Coverage is
// a horizontally scrolling matrix, so it takes the full canvas.
const MAX_WIDTH: Record<ResultTab, string> = {
  overview: "max-w-[1140px]",
  dashboard: "max-w-[1140px]",
  summary: "max-w-[900px]",
  alerts: "max-w-[900px]",
  "threat-intel": "max-w-[1140px]",
  coverage: "max-w-none",
};

export default function ResultsPage() {
  // `useSearchParams` (page number) needs a Suspense boundary above it during
  // prerender.
  return (
    <Suspense fallback={<Centered>Loading…</Centered>}>
      <ResultsView />
    </Suspense>
  );
}

function ResultsView() {
  const params = useParams<{ id: string; tab: string }>();
  const router = useRouter();
  const searchParams = useSearchParams();

  const uploadId = Number(params.id);
  const page = pageFromQuery(searchParams.get("page"));
  const query = searchParams.get("q") ?? "";
  const tab = tabFromParam(params.tab);

  const [analysis, setAnalysis] = useState<AnomaliesOut | null>(null);
  const [detail, setDetail] = useState<UploadDetail | null>(null);
  const [entriesLoading, setEntriesLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // An unknown tab segment (typo, stale link) is normalised to overview so the
  // URL always names a real view.
  useEffect(() => {
    if (Number.isInteger(uploadId) && !isResultTab(params.tab)) {
      router.replace(`/uploads/${uploadId}/${DEFAULT_TAB}`);
    }
  }, [uploadId, params.tab, router]);

  // The analysis view is page-independent: fetched once, so paging the table
  // never re-runs the narrative or the charts. Both requests are in flight
  // together — neither waits on the other.
  useEffect(() => {
    if (!getToken()) {
      router.replace("/login");
      return;
    }
    if (!Number.isInteger(uploadId)) {
      setError("That upload id is not valid.");
      return;
    }

    let cancelled = false;
    getAnomalies(uploadId)
      .then((data) => !cancelled && setAnalysis(data))
      .catch((err) => !cancelled && setError(errorMessage(err)));

    return () => {
      cancelled = true;
    };
  }, [uploadId, router]);

  useEffect(() => {
    if (!getToken() || !Number.isInteger(uploadId)) return;

    let cancelled = false;
    setEntriesLoading(true);
    getUpload(uploadId, { limit: PAGE_SIZE, offset: (page - 1) * PAGE_SIZE, q: query })
      .then((data) => !cancelled && setDetail(data))
      .catch((err) => !cancelled && setError(errorMessage(err)))
      .finally(() => {
        if (!cancelled) setEntriesLoading(false);
      });

    return () => {
      cancelled = true;
    };
  }, [uploadId, page, query]);

  const goToPage = useCallback(
    (next: number) => {
      const query = new URLSearchParams(searchParams.toString());
      if (next <= 1) query.delete("page");
      else query.set("page", String(next));

      const suffix = query.toString();
      router.replace(`/uploads/${uploadId}/${tab}${suffix ? `?${suffix}` : ""}`, {
        scroll: false,
      });
    },
    [router, searchParams, uploadId, tab],
  );

  // A new search resets to page 1 and rewrites `?q=` (dropping it when cleared),
  // keeping the search shareable and refresh-safe.
  const onSearch = useCallback(
    (next: string) => {
      const params = new URLSearchParams(searchParams.toString());
      const term = next.trim();
      if (term) params.set("q", term);
      else params.delete("q");
      params.delete("page");

      const suffix = params.toString();
      router.replace(`/uploads/${uploadId}/${tab}${suffix ? `?${suffix}` : ""}`, {
        scroll: false,
      });
    },
    [router, searchParams, uploadId, tab],
  );

  // `?page=` is user-editable and can outlive the entries it pointed at, so the
  // URL is corrected once the real (filtered) total is known rather than trusted.
  useEffect(() => {
    if (!detail) return;
    const lastPage = Math.max(1, Math.ceil(detail.entries_total / PAGE_SIZE));
    if (page > lastPage) goToPage(lastPage);
  }, [detail, page, goToPage]);

  // Findings come from the analysis view, so the table's markers stay put while
  // pages turn.
  const findings = useMemo(() => analysis?.findings ?? [], [analysis]);
  const flagged = useMemo(() => worstSeverityByEntry(findings), [findings]);

  const chatContext: ChatContext | null = analysis
    ? {
        totalEntries: analysis.total_entries,
        flaggedCount: analysis.flagged_count,
        findingCount: analysis.findings.length,
        narrative: analysis.narrative,
      }
    : null;

  if (error) {
    return (
      <div className="flex min-h-screen flex-col">
        <ConsoleHeader variant="app" uploadId={uploadId} activeTab={tab} />
        <Centered>
          <p className="text-error-text">{error}</p>
          <Link href="/upload" className="mt-4 inline-block text-[13px] text-accent hover:underline">
            ← Back to upload
          </Link>
        </Centered>
      </div>
    );
  }

  return (
    <div className="flex min-h-screen flex-col">
      <ConsoleHeader variant="app" uploadId={uploadId} activeTab={tab} />

      <main className={`mx-auto w-full flex-1 px-7 py-7 ${MAX_WIDTH[tab]}`}>
        {!detail ? (
          <p className="py-12 text-[14px] text-ink-muted">Loading analysis…</p>
        ) : (
          <ResultTabView
            tab={tab}
            detail={detail}
            analysis={analysis}
            findings={findings}
            flagged={flagged}
            page={page}
            query={query}
            onSearch={onSearch}
            entriesLoading={entriesLoading}
            onPageChange={goToPage}
            error={error}
          />
        )}
      </main>

      <AskClaude uploadId={uploadId} context={chatContext} />
    </div>
  );
}

function ResultTabView({
  tab,
  detail,
  analysis,
  findings,
  flagged,
  page,
  query,
  onSearch,
  entriesLoading,
  onPageChange,
  error,
}: {
  tab: ResultTab;
  detail: UploadDetail;
  analysis: AnomaliesOut | null;
  findings: AnomaliesOut["findings"];
  flagged: ReturnType<typeof worstSeverityByEntry>;
  page: number;
  query: string;
  onSearch: (q: string) => void;
  entriesLoading: boolean;
  onPageChange: (page: number) => void;
  error: string | null;
}) {
  const totalEntries = analysis?.total_entries ?? detail.summary.total_entries;
  const flaggedCount = analysis?.flagged_count ?? detail.summary.flagged_count;

  switch (tab) {
    case "overview":
      return (
        <OverviewTab
          upload={detail.upload}
          totalEntries={totalEntries}
          flaggedCount={flaggedCount}
          findings={findings}
          entries={detail.entries}
          flagged={flagged}
          page={page}
          pageSize={PAGE_SIZE}
          tableTotal={detail.entries_total}
          query={query}
          onSearch={onSearch}
          entriesLoading={entriesLoading}
          onPageChange={onPageChange}
          loadError={error}
        />
      );
    case "dashboard":
      return analysis ? (
        <DashboardTab analysis={analysis} entries={detail.entries} />
      ) : (
        <TabPlaceholder />
      );
    case "summary":
      return (
        <SummaryTab
          narrative={analysis?.narrative ?? detail.summary.narrative}
          llmOk={analysis?.llm_ok ?? detail.upload.llm_ok}
          findings={findings}
        />
      );
    case "alerts":
      return <AlertsTab findings={findings} />;
    case "threat-intel":
      return <ThreatIntelTab uploadId={detail.upload.id} />;
    case "coverage":
      return <CoverageTab uploadId={detail.upload.id} findings={findings} />;
  }
}

function TabPlaceholder() {
  return (
    <div className="grid gap-3.5 lg:grid-cols-[1fr_1.6fr]" aria-hidden="true">
      <div className="h-[300px] rounded-[10px] border border-border bg-surface" />
      <div className="h-[300px] rounded-[10px] border border-border bg-surface" />
    </div>
  );
}

function Centered({ children }: { children: React.ReactNode }) {
  return <main className="mx-auto max-w-4xl px-7 py-12 text-ink-muted">{children}</main>;
}

function pageFromQuery(raw: string | null): number {
  const parsed = Number(raw);
  return Number.isInteger(parsed) && parsed > 1 ? parsed : 1;
}

function errorMessage(err: unknown): string {
  return err instanceof Error ? err.message : "Something went wrong";
}
