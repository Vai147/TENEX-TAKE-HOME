"use client";

import { useRouter } from "next/navigation";
import { useMemo, useState } from "react";
import {
  Bar,
  BarChart,
  Cell,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";

import { useReducedMotion } from "@/hooks/useReducedMotion";
import { fetchAttackLayer, type AnomaliesOut, type LogEntryOut } from "@/lib/api";
import {
  buildTechniqueCells,
  TACTIC_ORDER,
  type TechniqueCell,
} from "@/lib/attack";
import {
  deriveBreakdowns,
  normalizeBreakdowns,
  orNotLoaded,
  type Breakdowns,
} from "@/lib/breakdowns";
import { detectorLabel, formatHour, formatNumber } from "@/lib/format";
import { CHART_INK, PIE_PALETTES, SERIES, SEVERITY_HEX } from "@/lib/palette";
import { SEVERITY_ORDER } from "@/lib/severity";

// Detector display order for the donut, matching the prototype.
const DETECTOR_ORDER = [
  "ip_burst",
  "rare_user_agent",
  "blocked_spike",
  "byte_volume",
  "off_hours",
];

type Kind = "allowed" | "blocked";

interface DashboardTabProps {
  analysis: AnomaliesOut;
  /** Loaded entries page — the source for tooltip IP/destination breakdowns. */
  entries: readonly LogEntryOut[];
}

export function DashboardTab({ analysis, entries }: DashboardTabProps) {
  const router = useRouter();
  const uploadId = analysis.upload_id;
  const breakdowns = useMemo<Breakdowns>(() => {
    return analysis.breakdowns
      ? normalizeBreakdowns(analysis.breakdowns)
      : deriveBreakdowns(entries, analysis.findings);
  }, [analysis.breakdowns, entries, analysis.findings]);

  const detectors = useMemo(() => buildDetectors(analysis, breakdowns), [analysis, breakdowns]);
  const totalFindings = analysis.findings.length;
  const detSummary = `${totalFindings} findings across ${detectors.length} detector${detectors.length === 1 ? "" : "s"}`;

  const techniques = useMemo(
    () => buildTechniqueCells(analysis.findings),
    [analysis.findings],
  );
  const mappedCount = techniques.reduce((sum, technique) => sum + technique.count, 0);
  const unmappedCount = analysis.findings.length - mappedCount;
  const attackSummary = `${techniques.length} observed technique${techniques.length === 1 ? "" : "s"} · ${mappedCount} mapped finding${mappedCount === 1 ? "" : "s"}`;

  return (
    <div className="flex flex-col gap-5">
      <div>
        <p className="text-[12px] font-medium text-ink-muted">Dashboard</p>
        <h1 className="mt-1 text-[20px] font-semibold text-ink-primary">
          Findings at a glance
        </h1>
      </div>

      <div className="grid gap-3.5 md:grid-cols-[1fr_1.6fr]">
        <Card>
          <CardHead title="Findings by detector" sub={detSummary} />
          <DetectorDonut
            detectors={detectors}
            total={totalFindings}
            onOpenAlerts={() => router.push(`/uploads/${uploadId}/alerts`)}
          />
        </Card>

        <Card className="flex flex-col">
          <div className="flex flex-wrap items-baseline justify-between gap-2">
            <CardHead title="Requests per hour" sub="stacked allowed vs blocked" />
            <Legend />
          </div>
          <HourlyBars timeline={analysis.timeline} breakdowns={breakdowns} />
        </Card>
      </div>

      <Card>
        <CardHead title="Top source IPs" sub="busiest talkers, allowed vs blocked" />
        <TopTalkers topTalkers={analysis.top_talkers} breakdowns={breakdowns} />
      </Card>

      <Card>
        <CardHead
          title="MITRE ATT&CK Matrix"
          sub={`${attackSummary} — observed techniques are highlighted by highest severity`}
        />
        <AttackMatrix
          techniques={techniques}
          breakdowns={breakdowns}
          onOpenAlerts={() => router.push(`/uploads/${uploadId}/alerts`)}
        />
        {unmappedCount > 0 && (
          <p className="mt-3 text-[11px] text-ink-faint">
            {unmappedCount} behavioural finding{unmappedCount === 1 ? "" : "s"} not mapped to ATT&amp;CK.
          </p>
        )}
        <NavigatorDownload uploadId={uploadId} disabled={mappedCount === 0} />
      </Card>
    </div>
  );
}

// ---- Compact ATT&CK matrix ----

function techniqueIps(technique: TechniqueCell, breakdowns: Breakdowns): string[] {
  const ips = new Set<string>();
  for (const type of technique.types) {
    for (const ip of breakdowns.detectorIps.get(type) ?? []) ips.add(ip);
  }
  return [...ips];
}

function AttackMatrix({
  techniques,
  breakdowns,
  onOpenAlerts,
}: {
  techniques: TechniqueCell[];
  breakdowns: Breakdowns;
  onOpenAlerts: () => void;
}) {
  if (techniques.length === 0) {
    return (
      <p className="mt-5 py-8 text-center text-[13px] text-ink-muted">
        No findings in this log mapped to an ATT&amp;CK technique.
      </p>
    );
  }

  // The whole ATT&CK kill chain is shown as columns for coverage context, but
  // every technique cell still comes from the log: tactics with no findings get
  // an empty placeholder rather than reference technique names.
  const byTactic = new Map<string, TechniqueCell[]>();
  for (const technique of techniques) {
    const cells = byTactic.get(technique.tactic) ?? [];
    cells.push(technique);
    byTactic.set(technique.tactic, cells);
  }

  return (
    <div className="mt-5 overflow-x-auto pb-2">
      <div
        className="grid min-w-[2180px] gap-1"
        style={{ gridTemplateColumns: `repeat(${TACTIC_ORDER.length}, minmax(150px, 1fr))` }}
      >
        {TACTIC_ORDER.map((tactic) => {
          const cells = byTactic.get(tactic) ?? [];
          const active = cells.length > 0;
          return (
            <div key={tactic} className="flex min-w-0 flex-col gap-1">
              <div
                className="flex min-h-[42px] items-center justify-center rounded-sm px-2 py-2 text-center text-[9px] font-semibold uppercase tracking-[0.03em] text-white"
                style={{ backgroundColor: "#343b5b", opacity: active ? 1 : 0.5 }}
              >
                {tactic}
              </div>

              {cells.map((technique) => {
                const color = SEVERITY_HEX[technique.severity];
                const ips = orNotLoaded(techniqueIps(technique, breakdowns));

                return (
                  <button
                    type="button"
                    key={technique.techniqueId}
                    onClick={onOpenAlerts}
                    className="min-h-[76px] rounded-sm border bg-card px-2 py-2 text-left shadow-sm transition-transform hover:-translate-y-0.5 hover:shadow-card focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
                    style={{
                      // Translucent severity wash layers over the card in either
                      // theme, instead of a fixed light fill.
                      backgroundImage: `linear-gradient(0deg, color-mix(in srgb, ${color} 14%, transparent), color-mix(in srgb, ${color} 14%, transparent))`,
                      borderColor: color,
                      borderTopWidth: 4,
                    }}
                    title={`${technique.count} finding${technique.count === 1 ? "" : "s"}; source IPs: ${ips.join(", ")}`}
                  >
                    <span className="flex items-start justify-between gap-1">
                      <span className="font-mono text-[9px] font-semibold" style={{ color }}>
                        {technique.techniqueId}
                      </span>
                      <span
                        className="rounded-full px-2 py-0.5 font-mono text-[10px] font-semibold text-white"
                        style={{ backgroundColor: color }}
                      >
                        {technique.count}
                      </span>
                    </span>
                    <span className="mt-1.5 block text-[10px] font-semibold leading-snug text-foreground">
                      {technique.techniqueName}
                    </span>
                    <span className="mt-1.5 block truncate font-mono text-[8px] text-muted-foreground">
                      {ips.join(", ")}
                    </span>
                  </button>
                );
              })}

              {!active && (
                <div className="flex min-h-[76px] items-center justify-center rounded-sm border border-dashed border-border bg-muted/20 text-[11px] text-muted-foreground">
                  —
                </div>
              )}
            </div>
          );
        })}
      </div>

      <div className="flex flex-wrap items-center gap-x-4 gap-y-1 border-t border-divider pt-3 text-[10px] text-ink-faint">
        <span>Badge = finding count</span>
        {SEVERITY_ORDER.map((severity) => (
          <span key={severity} className="inline-flex items-center gap-1 capitalize">
            <span
              className="h-2 w-2 rounded-[2px]"
              style={{ backgroundColor: SEVERITY_HEX[severity] }}
              aria-hidden="true"
            />
            {severity}
          </span>
        ))}
        <span className="ml-auto">Select a cell to open alerts</span>
      </div>
    </div>
  );
}

// ---- Detector donut ----

interface Detector {
  type: string;
  name: string;
  count: number;
  color: string;
  ips: string[];
}

function buildDetectors(analysis: AnomaliesOut, breakdowns: Breakdowns): Detector[] {
  const counts = new Map<string, number>();
  for (const finding of analysis.findings) {
    counts.set(finding.type, (counts.get(finding.type) ?? 0) + 1);
  }
  const palette = PIE_PALETTES[0];
  return [...counts.keys()]
    .sort((a, b) => rank(a) - rank(b))
    .map((type, i) => ({
      type,
      name: detectorLabel(type),
      count: counts.get(type) ?? 0,
      color: palette[i % palette.length],
      ips: orNotLoaded(breakdowns.detectorIps.get(type)),
    }));
}

function rank(type: string): number {
  const i = DETECTOR_ORDER.indexOf(type);
  return i === -1 ? 99 : i;
}

function DetectorDonut({
  detectors,
  total,
  onOpenAlerts,
}: {
  detectors: Detector[];
  total: number;
  onOpenAlerts: () => void;
}) {
  const reduced = useReducedMotion();
  const [hover, setHover] = useState<string | null>(null);
  const active = detectors.find((d) => d.type === hover) ?? null;

  return (
    <div className="mt-[22px] flex flex-wrap items-center gap-6">
      <div className="relative h-[150px] w-[150px] flex-none">
        <PieChart width={150} height={150}>
          <Pie
            data={detectors}
            dataKey="count"
            nameKey="name"
            cx="50%"
            cy="50%"
            innerRadius={43}
            outerRadius={75}
            stroke="none"
            isAnimationActive={!reduced}
            onMouseLeave={() => setHover(null)}
          >
            {detectors.map((d) => (
              <Cell
                key={d.type}
                fill={d.color}
                fillOpacity={hover === null || hover === d.type ? 1 : 0.3}
                style={{ cursor: "pointer", transition: "fill-opacity 0.15s" }}
                onMouseEnter={() => setHover(d.type)}
                onClick={onOpenAlerts}
              />
            ))}
          </Pie>
        </PieChart>

        <div className="pointer-events-none absolute inset-0 flex flex-col items-center justify-center">
          <span className="font-mono text-[22px] font-semibold text-ink-primary">
            {total}
          </span>
          <span className="text-[10px] tracking-[0.04em] text-ink-faint">findings</span>
        </div>

        {active && (
          <div
            className="pointer-events-none absolute left-[calc(100%+14px)] top-1/2 z-30 flex w-[230px] -translate-y-1/2 flex-col gap-1.5 rounded-lg border border-border bg-surface p-3 shadow-popover"
            style={{ borderTop: `2px solid ${active.color}` }}
          >
            <span
              className="text-[10px] font-semibold capitalize tracking-[0.04em]"
              style={{ color: active.color }}
            >
              {active.name} · {active.count} findings
            </span>
            <span className="text-[10px] font-medium text-ink-faint">Source IPs detected</span>
            {active.ips.map((ip, i) => (
              <span key={i} className="font-mono text-[11px] leading-relaxed text-[#475467]">
                • {ip}
              </span>
            ))}
            <span className="mt-0.5 text-[10px] text-ink-faint">click slice to open alerts</span>
          </div>
        )}
      </div>

      <ul className="flex min-w-[170px] flex-1 flex-col gap-2">
        {detectors.map((d) => (
          <li key={d.type} className="flex items-center gap-2 text-[12px]">
            <span
              className="h-2 w-2 flex-none rounded-[2px]"
              style={{ background: d.color }}
              aria-hidden="true"
            />
            <span className="text-ink-secondary">{d.name}</span>
            <span className="ml-auto font-mono font-semibold text-ink-primary">
              {d.count}
            </span>
          </li>
        ))}
      </ul>
    </div>
  );
}

function NavigatorDownload({
  uploadId,
  disabled,
}: {
  uploadId: number;
  disabled: boolean;
}) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function download() {
    setBusy(true);
    setError(null);
    try {
      const text = await fetchAttackLayer(uploadId);
      const url = URL.createObjectURL(new Blob([text], { type: "application/json" }));
      const a = document.createElement("a");
      a.href = url;
      a.download = `tenex-attack-${uploadId}.json`;
      a.click();
      URL.revokeObjectURL(url);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Download failed");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="mt-4 flex flex-wrap items-center gap-x-3 gap-y-1 border-t border-divider pt-3.5">
      <button
        type="button"
        onClick={download}
        disabled={disabled || busy}
        className="inline-flex items-center gap-1.5 text-[12px] font-medium text-accent transition-colors hover:text-accent-hover disabled:cursor-not-allowed disabled:text-ink-faint"
      >
        <span aria-hidden="true">↓</span>
        {busy ? "Preparing…" : "Download ATT&CK Navigator layer"}
      </button>
      <span className="text-[11px] text-ink-faint">
        open in MITRE ATT&CK Navigator
      </span>
      {error && <span className="text-[11px] text-error-text">{error}</span>}
    </div>
  );
}

// ---- Requests per hour ----

interface HourDatum {
  hour: string;
  allowed: number;
  blocked: number;
}

function HourlyBars({
  timeline,
  breakdowns,
}: {
  timeline: AnomaliesOut["timeline"];
  breakdowns: Breakdowns;
}) {
  const reduced = useReducedMotion();
  const [kind, setKind] = useState<Kind>("allowed");

  const data: HourDatum[] = timeline.map((b) => ({
    hour: b.start,
    allowed: b.requests - b.blocked,
    blocked: b.blocked,
  }));

  if (data.length === 0) {
    return (
      <p className="py-16 text-center text-[13px] text-ink-muted">
        No timestamps were parsed, so there is no timeline to draw.
      </p>
    );
  }

  return (
    <div className="mt-5 flex-1">
      <ResponsiveContainer width="100%" height={210}>
        <BarChart data={data} margin={{ top: 8, right: 4, bottom: 0, left: 4 }} barCategoryGap="18%">
          <XAxis
            dataKey="hour"
            tickFormatter={formatHour}
            tick={{ fill: CHART_INK.label, fontSize: 10, fontFamily: "var(--font-plex-mono)" }}
            tickLine={false}
            axisLine={{ stroke: CHART_INK.axis }}
            interval="preserveStartEnd"
            minTickGap={40}
          />
          <YAxis hide />
          <Tooltip
            cursor={{ fill: "rgba(16,24,40,0.04)" }}
            content={(props) => (
              <SegmentTip
                active={props.active}
                label={props.label as string | undefined}
                kind={kind}
                heading={(l) => formatHour(l)}
                itemsFor={(l) => breakdowns.hourIps.get(new Date(l).getHours())?.[kind] ?? []}
                itemsLabel="Source IPs"
                countFor={(l) => {
                  const row = data.find((d) => d.hour === l);
                  return row ? row[kind] : 0;
                }}
              />
            )}
          />
          <Bar
            dataKey="blocked"
            stackId="traffic"
            fill={SERIES.blocked}
            radius={[2, 2, 0, 0]}
            isAnimationActive={!reduced}
            onMouseEnter={() => setKind("blocked")}
          />
          <Bar
            dataKey="allowed"
            stackId="traffic"
            fill={SERIES.allowed}
            isAnimationActive={!reduced}
            onMouseEnter={() => setKind("allowed")}
          />
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}

// ---- Top source IPs ----

interface TalkerDatum {
  ip: string;
  allowed: number;
  blocked: number;
  total: number;
}

function TopTalkers({
  topTalkers,
  breakdowns,
}: {
  topTalkers: AnomaliesOut["top_talkers"];
  breakdowns: Breakdowns;
}) {
  const reduced = useReducedMotion();
  const [kind, setKind] = useState<Kind>("allowed");

  const data: TalkerDatum[] = topTalkers.map((t) => ({
    ip: t.src_ip,
    allowed: t.requests - t.blocked,
    blocked: t.blocked,
    total: t.requests,
  }));

  if (data.length === 0) {
    return (
      <p className="py-10 text-center text-[13px] text-ink-muted">
        No source IPs were parsed from this file.
      </p>
    );
  }

  return (
    <div className="mt-4">
      <ResponsiveContainer width="100%" height={Math.max(160, data.length * 34 + 8)}>
        <BarChart
          data={data}
          layout="vertical"
          margin={{ top: 0, right: 8, bottom: 0, left: 0 }}
          barCategoryGap="26%"
        >
          <XAxis type="number" hide />
          <YAxis
            type="category"
            dataKey="ip"
            width={118}
            tick={{ fill: "#1f2733", fontSize: 12, fontFamily: "var(--font-plex-mono)" }}
            tickLine={false}
            axisLine={false}
          />
          <Tooltip
            cursor={{ fill: "rgba(16,24,40,0.04)" }}
            content={(props) => (
              <SegmentTip
                active={props.active}
                label={props.label as string | undefined}
                kind={kind}
                heading={(l) => l}
                itemsFor={(l) => breakdowns.talkerDests.get(l)?.[kind] ?? []}
                itemsLabel="Top destinations"
                countFor={(l) => {
                  const row = data.find((d) => d.ip === l);
                  return row ? row[kind] : 0;
                }}
              />
            )}
          />
          <Bar
            dataKey="allowed"
            stackId="talker"
            fill={SERIES.allowed}
            radius={[2, 0, 0, 2]}
            isAnimationActive={!reduced}
            onMouseEnter={() => setKind("allowed")}
          />
          <Bar
            dataKey="blocked"
            stackId="talker"
            fill={SERIES.blocked}
            radius={[0, 2, 2, 0]}
            isAnimationActive={!reduced}
            onMouseEnter={() => setKind("blocked")}
          />
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}

// ---- Shared segment tooltip ----

function SegmentTip({
  active,
  label,
  kind,
  heading,
  itemsFor,
  itemsLabel,
  countFor,
}: {
  active?: boolean;
  label?: string;
  kind: Kind;
  heading: (label: string) => string;
  itemsFor: (label: string) => string[];
  itemsLabel: string;
  countFor: (label: string) => number;
}) {
  if (!active || !label) return null;
  const color = kind === "blocked" ? SERIES.blocked : SERIES.allowed;
  const items = orNotLoaded(itemsFor(label));

  return (
    <div
      className="pointer-events-none flex w-[230px] flex-col gap-1.5 rounded-lg border border-border bg-surface p-3 shadow-popover"
      style={{ borderTop: `2px solid ${color}` }}
    >
      <span className="text-[10px] font-semibold capitalize tracking-[0.04em]" style={{ color }}>
        {heading(label)} · {kind} {formatNumber(countFor(label))}
      </span>
      <span className="text-[10px] font-medium text-ink-faint">{itemsLabel}</span>
      {items.map((item, i) => (
        <span key={i} className="font-mono text-[11px] leading-relaxed text-[#475467]">
          • {item}
        </span>
      ))}
    </div>
  );
}

// ---- Card chrome ----

function Card({ children, className = "" }: { children: React.ReactNode; className?: string }) {
  return (
    <div className={`rounded-[10px] border border-border bg-surface px-5 py-[18px] ${className}`}>
      {children}
    </div>
  );
}

function CardHead({ title, sub }: { title: string; sub: string }) {
  return (
    <div>
      <h3 className="text-[14px] font-semibold text-ink-primary">{title}</h3>
      <p className="mt-1 text-[12px] text-ink-muted">{sub}</p>
    </div>
  );
}

function Legend() {
  return (
    <div className="flex gap-3.5">
      <LegendItem color={SERIES.allowed} label="allowed" />
      <LegendItem color={SERIES.blocked} label="blocked" />
    </div>
  );
}

function LegendItem({ color, label }: { color: string; label: string }) {
  return (
    <span className="inline-flex items-center gap-1.5 text-[12px] text-ink-muted">
      <span className="h-2 w-2 rounded-[2px]" style={{ background: color }} aria-hidden="true" />
      {label}
    </span>
  );
}
