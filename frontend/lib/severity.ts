import type { AnomalyFindingOut, Severity } from "./api";

// Worst first: the order an analyst works the queue in, so index 0 is the thing
// to open. `worstSeverity` relies on this ordering.
export const SEVERITY_ORDER = ["critical", "high", "medium", "low"] as const;

export const SEVERITY_FILL: Record<Severity, string> = {
  critical: "bg-sev-critical",
  high: "bg-sev-high",
  medium: "bg-sev-medium",
  low: "bg-sev-low",
};

/** Findings ordered the way an analyst works the queue: worst severity first,
 *  and within a severity the most confident detector first. Index 0 is the one
 *  finding to surface as the headline. Pure — returns a new array. */
export function findingsWorstFirst(
  findings: readonly AnomalyFindingOut[],
): AnomalyFindingOut[] {
  return [...findings].sort((a, b) => {
    const bySeverity =
      SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity);
    return bySeverity !== 0 ? bySeverity : b.confidence - a.confidence;
  });
}

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
