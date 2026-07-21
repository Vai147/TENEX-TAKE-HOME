"use client";

import Link from "next/link";
import { useEffect, useMemo, useState } from "react";

import {
  COVERAGE_CATALOG,
  TIER_LABEL,
  TIER_MEANING,
  catalogCounts,
  countTiers,
  observedOverlay,
  percent,
  weightedCoverage,
  type CoverageTactic,
  type CoverageTechnique,
  type CoverageTier,
} from "@/lib/coverage";
import {
  createCoverageExplanation,
  getCoverageExplanations,
  type AnomalyFindingOut,
  type CoverageExplanationOut,
} from "@/lib/api";
import type { TechniqueCell } from "@/lib/attack";
import { COVERAGE_HEX, SEVERITY_HEX } from "@/lib/palette";

const TIERS: readonly CoverageTier[] = ["covered", "partial", "none"];

interface CoverageTabProps {
  uploadId: number;
  findings: readonly AnomalyFindingOut[];
  catalog?: readonly CoverageTactic[];
}

/** Detection-coverage heatmap: every catalogued technique as a cell, coloured by
 *  coverage tier, one column per tactic across the kill chain. */
export function CoverageTab({ uploadId, findings, catalog = COVERAGE_CATALOG }: CoverageTabProps) {
  // Purely local view state — filtering and selection never hit the server.
  const [filter, setFilter] = useState<CoverageTier | "observed" | null>(null);
  const [selected, setSelected] = useState<string | null>(null);
  const [inspected, setInspected] = useState<string | null>(null);
  const [explanations, setExplanations] = useState<
    ReadonlyMap<string, CoverageExplanationOut>
  >(new Map());
  const [explanationLoading, setExplanationLoading] = useState<string | null>(null);
  const [explanationError, setExplanationError] = useState<string | null>(null);

  const counts = useMemo(() => catalogCounts(catalog), [catalog]);
  const observed = useMemo(() => observedOverlay(findings, catalog), [findings, catalog]);
  const weighted = weightedCoverage(counts);

  useEffect(() => {
    let cancelled = false;
    getCoverageExplanations(uploadId)
      .then((rows) => {
        if (!cancelled) {
          setExplanations(new Map(rows.map((row) => [row.technique_id, row])));
        }
      })
      .catch(() => {
        // A hover can retry through the create endpoint; cached prose is optional.
      });
    return () => {
      cancelled = true;
    };
  }, [uploadId]);

  const inspectedCell = useMemo(() => {
    if (!inspected) return null;
    for (const tactic of catalog) {
      const technique = tactic.techniques.find((item) => item.id === inspected);
      if (technique) {
        return {
          tactic,
          technique,
          observation:
            technique.tier === "covered"
              ? observed.byTechnique.get(technique.id)
              : undefined,
        };
      }
    }
    return null;
  }, [catalog, inspected, observed]);

  useEffect(() => {
    if (
      !inspectedCell ||
      inspectedCell.technique.tier === "none" ||
      explanations.has(inspectedCell.technique.id)
    ) {
      return;
    }

    const techniqueId = inspectedCell.technique.id;
    const timer = window.setTimeout(() => {
      setExplanationLoading(techniqueId);
      setExplanationError(null);
      createCoverageExplanation(uploadId, techniqueId)
        .then((row) => {
          setExplanations((current) => new Map(current).set(row.technique_id, row));
        })
        .catch((error: unknown) => {
          setExplanationError(
            error instanceof Error ? error.message : "Explanation unavailable",
          );
        })
        .finally(() => setExplanationLoading((current) => (current === techniqueId ? null : current)));
    }, 350);

    return () => window.clearTimeout(timer);
  }, [explanations, inspectedCell, uploadId]);

  const selectedCell = useMemo(() => {
    if (!selected) return null;
    for (const tactic of catalog) {
      const technique = tactic.techniques.find((t) => cellId(tactic, t) === selected);
      if (technique) {
        return {
          tactic,
          technique,
          observation: technique.tier === "covered" ? observed.byTechnique.get(technique.id) : undefined,
        };
      }
    }
    return null;
  }, [catalog, observed, selected]);

  return (
    <div className="flex flex-col">
      <header className="flex flex-wrap items-start justify-between gap-8">
        <div>
          <p className="text-[12px] font-medium text-ink-muted">Coverage</p>
          <h1 className="mt-1 text-[20px] font-semibold tracking-[-0.01em] text-ink-primary">
            ATT&amp;CK coverage matrix
          </h1>
          <p className="mt-1.5 text-[13px] text-ink-muted">
            Enterprise detection coverage · SOC visibility heatmap
          </p>
        </div>

        <div className="flex items-center gap-7">
          <div className="text-right">
            <div
              className="font-mono text-[30px] font-semibold leading-none"
              style={{ color: COVERAGE_HEX.covered.fill }}
            >
              {weighted}%
            </div>
            <div className="mt-1.5 text-[10px] font-semibold uppercase tracking-[0.1em] text-ink-faint">
              Weighted coverage
            </div>
          </div>

          <div className="w-[260px]">
            <Meter counts={counts} height="h-2" />
            <div className="mt-2 flex items-center justify-between font-mono text-[11px] text-ink-faint">
              <span>{counts.total} techniques</span>
              <span>
                {counts.covered}C · {counts.partial}P · {counts.none}N
              </span>
            </div>
          </div>

          <div className="border-l border-border pl-7 text-right">
            <div className="font-mono text-[24px] font-semibold leading-none text-ink-primary">
              {observed.byTechnique.size} of {counts.covered}
            </div>
            <div className="mt-1.5 text-[10px] font-semibold uppercase tracking-[0.1em] text-ink-faint">
              Detectable techniques triggered
            </div>
          </div>
        </div>
      </header>

      <div className="mt-[18px] flex flex-wrap items-center justify-between gap-5">
        <div className="flex gap-2.5" role="group" aria-label="Filter by coverage tier">
          {TIERS.map((tier) => (
            <TierChip
              key={tier}
              tier={tier}
              count={counts[tier]}
              active={filter === tier}
              onToggle={() => setFilter((current) => (current === tier ? null : tier))}
            />
          ))}
          <span className="mx-0.5 h-6 w-px self-center bg-border" aria-hidden="true" />
          <ObservedChip
            count={observed.byTechnique.size}
            active={filter === "observed"}
            onToggle={() => setFilter((current) => (current === "observed" ? null : "observed"))}
          />
        </div>
      </div>

      <CoverageExplanationStrip
        cell={inspectedCell}
        explanation={
          inspectedCell ? explanations.get(inspectedCell.technique.id) : undefined
        }
        loading={
          inspectedCell !== null &&
          explanationLoading === inspectedCell.technique.id
        }
        error={explanationError}
      />

      <div className="flex items-start gap-3 overflow-x-auto pb-3 pt-5">
        {catalog.map((tactic) => (
          <TacticColumn
            key={tactic.id}
            tactic={tactic}
            filter={filter}
            selected={selected}
            observed={observed.byTechnique}
            onInspect={setInspected}
            onSelect={(id) => setSelected((current) => (current === id ? null : id))}
          />
        ))}
      </div>


      {observed.uncatalogued.length > 0 && (
        <p className="mt-1 text-[11px] text-ink-faint">
          {observed.uncatalogued.length} observed ATT&amp;CK technique{observed.uncatalogued.length === 1 ? "" : "s"} not in the coverage catalogue.
        </p>
      )}

      <DetailStrip cell={selectedCell} uploadId={uploadId} />
    </div>
  );
}

function ObservedChip({ count, active, onToggle }: { count: number; active: boolean; onToggle: () => void }) {
  return (
    <button
      type="button"
      onClick={onToggle}
      aria-pressed={active}
      className={`inline-flex items-center gap-2 rounded-full border bg-card px-3 py-1.5 pl-2.5 transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent ${active ? "border-accent" : "border-border-strong hover:border-ink-faint"}`}
    >
      <span className="relative h-[13px] w-[13px] rounded" style={{ background: COVERAGE_HEX.covered.fill }}>
        <span className="absolute inset-[3px] rounded-full bg-white" />
      </span>
      <span className="text-[13px] font-medium text-ink-secondary">Observed</span>
      <span className="font-mono text-[13px] font-semibold text-ink-primary">{count}</span>
    </button>
  );
}

function cellId(tactic: CoverageTactic, technique: CoverageTechnique): string {
  return `${tactic.id}-${technique.id}`;
}

/** Two-segment bar: covered, then partial, over a track of everything else. */
function Meter({ counts, height }: { counts: ReturnType<typeof countTiers>; height: string }) {
  return (
    <div className={`flex ${height} overflow-hidden rounded-full bg-divider`}>
      <div
        style={{ width: percent(counts.covered, counts.total), background: COVERAGE_HEX.covered.fill }}
      />
      <div
        style={{ width: percent(counts.partial, counts.total), background: COVERAGE_HEX.partial.fill }}
      />
    </div>
  );
}

function TierChip({
  tier,
  count,
  active,
  onToggle,
}: {
  tier: CoverageTier;
  count: number;
  active: boolean;
  onToggle: () => void;
}) {
  return (
    <button
      type="button"
      onClick={onToggle}
      aria-pressed={active}
      className={`inline-flex items-center gap-2 rounded-full border bg-card px-3 py-1.5 pl-2.5 transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent ${
        active ? "border-accent" : "border-border-strong hover:border-ink-faint"
      }`}
    >
      <Swatch tier={tier} />
      <span className="text-[13px] font-medium text-ink-secondary">{TIER_LABEL[tier]}</span>
      <span className="font-mono text-[13px] font-semibold text-ink-primary">{count}</span>
    </button>
  );
}

function Swatch({ tier }: { tier: CoverageTier }) {
  if (tier === "none") {
    return <span className="h-[13px] w-[13px] rounded border border-dashed border-ink-faint" />;
  }
  return (
    <span
      className="h-[13px] w-[13px] rounded"
      style={{ background: COVERAGE_HEX[tier].fill }}
    />
  );
}

function TacticColumn({
  tactic,
  filter,
  selected,
  observed,
  onInspect,
  onSelect,
}: {
  tactic: CoverageTactic;
  filter: CoverageTier | "observed" | null;
  selected: string | null;
  observed: ReadonlyMap<string, TechniqueCell>;
  onInspect: (techniqueId: string) => void;
  onSelect: (id: string) => void;
}) {
  const counts = countTiers(tactic.techniques);

  return (
    <section className="flex shrink-0 grow-0 basis-[200px] flex-col gap-2.5" aria-label={tactic.name}>
      <header className="rounded-[10px] border border-border bg-surface-alt px-3.5 py-3">
        <h2 className="min-h-[36px] text-[14px] font-semibold leading-tight text-ink-primary">
          {tactic.name}
        </h2>
        <div className="mt-1.5 flex items-baseline justify-between font-mono text-[11px] text-ink-faint">
          <span>{tactic.id}</span>
          <span>{counts.total} tech</span>
        </div>
        <div className="mt-2">
          <Meter counts={counts} height="h-1" />
        </div>
      </header>

      {tactic.techniques.map((technique) => (
        <TechniqueCellButton
          key={technique.id}
          technique={technique}
          observation={technique.tier === "covered" ? observed.get(technique.id) : undefined}
          dimmed={filter !== null && (filter === "observed" ? !observed.has(technique.id) : filter !== technique.tier)}
          selected={selected === cellId(tactic, technique)}
          onInspect={() => onInspect(technique.id)}
          onSelect={() => onSelect(cellId(tactic, technique))}
        />
      ))}
    </section>
  );
}

function TechniqueCellButton({
  technique,
  dimmed,
  selected,
  observation,
  onInspect,
  onSelect,
}: {
  technique: CoverageTechnique;
  dimmed: boolean;
  selected: boolean;
  observation?: TechniqueCell;
  onInspect: () => void;
  onSelect: () => void;
}) {
  const solid = technique.tier === "none" ? null : COVERAGE_HEX[technique.tier];

  return (
    <button
      type="button"
      onClick={onSelect}
      onMouseEnter={onInspect}
      onFocus={onInspect}
      aria-pressed={selected}
      className={`flex min-h-[70px] w-full flex-col gap-1.5 rounded-[10px] border px-3 py-2.5 text-left transition-[transform,box-shadow,opacity] duration-[120ms] hover:-translate-y-0.5 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent ${
        solid ? "shadow-sm" : "border-dashed border-border-strong bg-card"
      } ${dimmed ? "opacity-30" : "opacity-100"} ${
        selected ? "ring-2 ring-accent ring-offset-2 ring-offset-canvas" : ""
      }`}
      style={solid ? { background: solid.fill, borderColor: solid.border } : undefined}
      title={TIER_MEANING[technique.tier]}
    >
      <span className="flex w-full items-center justify-between gap-2">
        <span className="font-mono text-[11px] font-semibold" style={{ color: solid?.code }}>
          {technique.id}
        </span>
        {observation && (
          <span
            className="inline-flex items-center gap-1.5 rounded-full bg-white/90 px-2 py-0.5 font-mono text-[10px] font-semibold shadow-sm"
            style={{ color: SEVERITY_HEX[observation.severity] }}
            aria-label={`${observation.count} findings, worst severity ${observation.severity}`}
          >
            <span className="h-1.5 w-1.5 rounded-full" style={{ background: SEVERITY_HEX[observation.severity] }} />
            {observation.count}
          </span>
        )}
      </span>
      <span
        className={`text-[13px] font-semibold leading-tight ${solid ? "" : "text-ink-faint"}`}
        style={{ color: solid?.name }}
      >
        {technique.name}
      </span>
    </button>
  );
}

function CoverageExplanationStrip({
  cell,
  explanation,
  loading,
  error,
}: {
  cell: {
    tactic: CoverageTactic;
    technique: CoverageTechnique;
    observation?: TechniqueCell;
  } | null;
  explanation?: CoverageExplanationOut;
  loading: boolean;
  error: string | null;
}) {
  const explainable = cell && cell.technique.tier !== "none";

  return (
    <aside className="mt-4 min-h-[86px] rounded-[10px] border border-border bg-card px-4 py-3 shadow-sm" aria-live="polite">
      {!cell && (
        <p className="text-[12px] text-ink-faint">
          Hover a covered or partial technique to see why it triggered, stayed silent, or remains a detection gap.
        </p>
      )}
      {cell && !explainable && (
        <>
          <p className="font-mono text-[11px] font-semibold text-ink-faint">{cell.technique.id} · No proxy visibility</p>
          <p className="mt-1.5 text-[12px] leading-relaxed text-ink-muted">This technique needs telemetry such as EDR, identity, email, or network sensors; the proxy log cannot support an evidence-grounded explanation.</p>
        </>
      )}
      {explainable && (
        <>
          <div className="flex flex-wrap items-center gap-2">
            <span className="font-mono text-[11px] font-semibold text-ink-primary">{cell.technique.id}</span>
            <span className="text-[12px] font-semibold text-ink-primary">{cell.technique.name}</span>
            {cell.observation && <span className="font-mono text-[10px] text-ink-muted">{cell.observation.count} finding{cell.observation.count === 1 ? "" : "s"} · {cell.observation.severity} worst</span>}
            {explanation && <span className="ml-auto rounded-full border border-border px-2 py-0.5 font-mono text-[9px] uppercase tracking-[0.08em] text-ink-faint">{explanation.source === "ai" ? "Cached AI" : "Grounded fallback"}</span>}
          </div>
          <p className="mt-1.5 text-[12px] leading-relaxed text-ink-muted">
            {explanation?.explanation ?? (loading ? "Generating and caching explanation…" : error ?? "Preparing explanation…")}
          </p>
        </>
      )}
    </aside>
  );
}

/** Reserves its own height so selecting a cell never shifts the matrix above it. */
function DetailStrip({
  cell,
  uploadId,
}: {
  cell: { tactic: CoverageTactic; technique: CoverageTechnique; observation?: TechniqueCell } | null;
  uploadId: number;
}) {
  return (
    <div
      aria-live="polite"
      className={`mt-4 flex flex-wrap items-center gap-3.5 rounded-[10px] border border-border bg-card px-[18px] py-3.5 shadow-sm transition-opacity duration-150 ${
        cell ? "opacity-100" : "invisible opacity-0"
      }`}
    >
      <span
        className="font-mono text-[12px] font-semibold"
        style={{ color: COVERAGE_HEX.covered.fill }}
      >
        {cell?.technique.id}
      </span>
      <span className="text-[14px] font-semibold text-ink-primary">{cell?.technique.name}</span>
      <span className="text-[13px] text-ink-muted">
        {cell ? `${cell.tactic.name} · ${TIER_MEANING[cell.technique.tier]}` : null}
      </span>
      {cell?.observation && (
        <span className="inline-flex items-center gap-1.5 text-[12px] font-medium capitalize" style={{ color: SEVERITY_HEX[cell.observation.severity] }}>
          <span className="h-2 w-2 rounded-full" style={{ background: SEVERITY_HEX[cell.observation.severity] }} />
          {cell.observation.count} finding{cell.observation.count === 1 ? "" : "s"} · {cell.observation.severity} worst
        </span>
      )}
      <Link
        href={`/uploads/${uploadId}/alerts`}
        tabIndex={cell ? undefined : -1}
        className="ml-auto text-[12px] font-medium text-accent hover:underline"
      >
        Open in Alerts →
      </Link>
    </div>
  );
}
