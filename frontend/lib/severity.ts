import type { AnomalyFindingOut, Severity } from "./api";

// Worst first: the order an analyst works the queue in, so index 0 is the thing
// to open. `worstSeverity` relies on this ordering.
export const SEVERITY_ORDER = ["critical", "high", "medium", "low"] as const;

// Alert-card tag: a hairline outline and label in the severity's own colour on a
// white card. The colour carries no meaning alone — every use pairs it with the
// severity word.
export const SEVERITY_BADGE: Record<Severity, string> = {
  critical: "border-sev-critical text-sev-critical",
  high: "border-sev-high text-sev-high",
  medium: "border-sev-medium text-sev-medium",
  low: "border-sev-low text-sev-low",
};

export const SEVERITY_FILL: Record<Severity, string> = {
  critical: "bg-sev-critical",
  high: "bg-sev-high",
  medium: "bg-sev-medium",
  low: "bg-sev-low",
};

export interface SeverityCount {
  severity: Severity;
  count: number;
}

/** Findings per severity, worst first. Empty bands are kept: "no criticals" is
 *  a fact an analyst wants stated, not an absence to hide. */
export function severityMix(findings: readonly AnomalyFindingOut[]): SeverityCount[] {
  return SEVERITY_ORDER.map((severity) => ({
    severity,
    count: findings.filter((finding) => finding.severity === severity).length,
  }));
}

/** The worst severity flagged against each entry, keyed by entry id.
 *
 *  One entry can anchor several findings, and a row can only wear one marker —
 *  it should be the one that gets the analyst to look. */
export function worstSeverityByEntry(
  findings: readonly AnomalyFindingOut[],
): ReadonlyMap<number, Severity> {
  const worst = new Map<number, Severity>();
  for (const finding of findings) {
    if (finding.entry_id === null) continue;
    const current = worst.get(finding.entry_id);
    if (
      current === undefined ||
      SEVERITY_ORDER.indexOf(finding.severity) < SEVERITY_ORDER.indexOf(current)
    ) {
      worst.set(finding.entry_id, finding.severity);
    }
  }
  return worst;
}
