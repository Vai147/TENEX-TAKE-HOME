// ATT&CK presentation helpers. The mapping itself is owned by the backend
// (app/attack.py) and arrives on each finding as `tactic` / `technique_id` /
// `technique_name`; this file only rolls findings up into technique-level cells.

import type { AnomalyFindingOut, Severity } from "./api";
import { SEVERITY_ORDER } from "./severity";

export const TACTIC_ORDER: readonly string[] = [
  "Reconnaissance",
  "Resource Development",
  "Initial Access",
  "Execution",
  "Persistence",
  "Privilege Escalation",
  "Defense Evasion",
  "Credential Access",
  "Discovery",
  "Lateral Movement",
  "Collection",
  "Command and Control",
  "Exfiltration",
  "Impact",
];

export interface TechniqueCell {
  tactic: string;
  techniqueId: string;
  techniqueName: string;
  count: number;
  severity: Severity;
  /** Finding types feeding this technique, used to resolve affected IPs. */
  types: string[];
}

function tacticOrder(tactic: string): number {
  const index = TACTIC_ORDER.indexOf(tactic);
  return index === -1 ? TACTIC_ORDER.length : index;
}

/** Roll mapped findings up by ATT&CK technique in kill-chain order.
 * Unmapped behavioural findings remain useful signals, but are not ATT&CK coverage.
 */
export function buildTechniqueCells(
  findings: readonly AnomalyFindingOut[],
): TechniqueCell[] {
  const groups = new Map<
    string,
    {
      tactic: string;
      techniqueName: string;
      count: number;
      severity: Severity;
      types: Set<string>;
    }
  >();

  for (const finding of findings) {
    if (!finding.technique_id || !finding.tactic) continue;

    const group = groups.get(finding.technique_id) ?? {
      tactic: finding.tactic,
      techniqueName: finding.technique_name ?? "Unknown technique",
      count: 0,
      severity: finding.severity,
      types: new Set<string>(),
    };
    group.count += 1;
    if (
      SEVERITY_ORDER.indexOf(finding.severity) <
      SEVERITY_ORDER.indexOf(group.severity)
    ) {
      group.severity = finding.severity;
    }
    group.types.add(finding.type);
    groups.set(finding.technique_id, group);
  }

  return [...groups.entries()]
    .map(([techniqueId, group]) => ({
      tactic: group.tactic,
      techniqueId,
      techniqueName: group.techniqueName,
      count: group.count,
      severity: group.severity,
      types: [...group.types],
    }))
    .sort((a, b) => {
      const byTactic = tacticOrder(a.tactic) - tacticOrder(b.tactic);
      if (byTactic !== 0) return byTactic;
      const bySeverity =
        SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity);
      return bySeverity !== 0
        ? bySeverity
        : a.techniqueId.localeCompare(b.techniqueId);
    });
}
