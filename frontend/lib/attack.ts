// ATT&CK presentation helpers. The mapping itself is owned by the backend
// (app/attack.py) and arrives on each finding as `tactic` / `technique_id` /
// `technique_name`; this file only decides display order and colour and rolls
// findings up into pie slices.

import type { AnomalyFindingOut } from "./api";
import { ATTACK_TACTIC_HEX } from "./palette";

// Findings with no ATT&CK technique (e.g. off_hours) are grouped here.
export const UNMAPPED_TACTIC = "Behavioural";

// Kill-chain order: recon → initial access → credential access → C2 → exfil,
// with the unmapped behavioural bucket last.
export const TACTIC_ORDER: readonly string[] = [
  "Reconnaissance",
  "Initial Access",
  "Credential Access",
  "Command and Control",
  "Exfiltration",
  UNMAPPED_TACTIC,
];

export interface TacticSlice {
  tactic: string;
  count: number;
  color: string;
  /** e.g. "T1110 Brute Force" — the technique(s) feeding this tactic. */
  techniques: string[];
  /** Finding `type`s feeding this tactic, for cross-referencing IP breakdowns. */
  types: string[];
}

function order(tactic: string): number {
  const i = TACTIC_ORDER.indexOf(tactic);
  return i === -1 ? TACTIC_ORDER.length : i;
}

/** Roll findings up into kill-chain-ordered ATT&CK tactic slices. */
export function buildTacticSlices(
  findings: readonly AnomalyFindingOut[],
): TacticSlice[] {
  const groups = new Map<
    string,
    { count: number; techniques: Set<string>; types: Set<string> }
  >();

  for (const finding of findings) {
    const tactic = finding.tactic ?? UNMAPPED_TACTIC;
    const group =
      groups.get(tactic) ?? { count: 0, techniques: new Set(), types: new Set() };
    group.count += 1;
    if (finding.technique_id) {
      group.techniques.add(
        `${finding.technique_id} ${finding.technique_name ?? ""}`.trim(),
      );
    }
    group.types.add(finding.type);
    groups.set(tactic, group);
  }

  return [...groups.entries()]
    .map(([tactic, group]) => ({
      tactic,
      count: group.count,
      color: ATTACK_TACTIC_HEX[tactic] ?? ATTACK_TACTIC_HEX[UNMAPPED_TACTIC],
      techniques: [...group.techniques],
      types: [...group.types],
    }))
    .sort((a, b) => order(a.tactic) - order(b.tactic));
}
