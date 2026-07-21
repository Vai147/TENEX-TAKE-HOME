// Detection-coverage model behind the Coverage tab.
//
// This is a *planning* view — what the platform can detect at all — as opposed
// to the Dashboard ATT&CK matrix, which shows what one uploaded log actually
// observed. Nothing here depends on an upload.
//
// Tiers are derived, not hand-authored, so the board cannot drift into claiming
// coverage the product does not have:
//   covered — a detector in backend/app/attack.py emits this technique
//   partial — ZScaler web-proxy logs carry signal for it, but no detector owns it
//   none    — outside what a web proxy can see; endpoint/EDR telemetry required
//
// When coverage becomes per-tenant config (or is computed server-side from the
// enabled rule set), replace DETECTED / PARTIAL with that source. CATALOG and
// everything downstream stay as they are.

import { buildTechniqueCells, type TechniqueCell } from "./attack";
import type { AnomalyFindingOut } from "./api";

export type CoverageTier = "covered" | "partial" | "none";

export interface CoverageTechnique {
  id: string;
  name: string;
  tier: CoverageTier;
}

export interface CoverageTactic {
  id: string;
  name: string;
  techniques: CoverageTechnique[];
}

/** Mirrors `_FINDING_ATTACK` in backend/app/attack.py — one technique per detector. */
const DETECTED: ReadonlySet<string> = new Set([
  "T1595", // blocked_spike   → Active Scanning
  "T1190", // rare_user_agent → Exploit Public-Facing Application
  "T1110", // ip_burst        → Brute Force
  "T1071", // threat_intel    → Application Layer Protocol
  "T1048", // byte_volume     → Exfiltration Over Alternative Protocol
  "T1046", // host_sweep      → Network Service Discovery
  "T1105", // tool_download   → Ingress Tool Transfer
  "T1567", // cloud_upload    → Exfiltration Over Web Service
]);

/** Visible in proxy telemetry (URLs, verdicts, byte counts, user agents) but not
 *  yet claimed by a detector — a gap an analyst can close, not a blind spot. */
const PARTIAL: ReadonlySet<string> = new Set([
  "T1566",
  "T1189",
  "T1133",
  "T1071.004",
  "T1573",
  "T1090",
  "T1041",
  "T1102",
]);

function tierFor(techniqueId: string): CoverageTier {
  if (DETECTED.has(techniqueId)) return "covered";
  if (PARTIAL.has(techniqueId)) return "partial";
  return "none";
}

// Enterprise reference catalogue, kill-chain ordered. Trimmed to the techniques
// worth showing a proxy-log analyst rather than the full ATT&CK corpus.
const RAW: readonly (readonly [string, string, readonly (readonly [string, string])[]])[] = [
  ["TA0043", "Reconnaissance", [
    ["T1595", "Active Scanning"],
    ["T1592", "Gather Victim Host Information"],
    ["T1590", "Gather Victim Network Information"],
    ["T1598", "Phishing for Information"],
  ]],
  ["TA0001", "Initial Access", [
    ["T1190", "Exploit Public-Facing App"],
    ["T1566", "Phishing"],
    ["T1133", "External Remote Services"],
    ["T1189", "Drive-by Compromise"],
    ["T1078", "Valid Accounts"],
    ["T1195", "Supply Chain Compromise"],
  ]],
  ["TA0002", "Execution", [
    ["T1059", "Command & Scripting Interpreter"],
    ["T1059.001", "PowerShell"],
    ["T1204", "User Execution"],
    ["T1053", "Scheduled Task"],
    ["T1047", "Windows Management Instrumentation"],
  ]],
  ["TA0003", "Persistence", [
    ["T1547", "Boot/Logon Autostart Execution"],
    ["T1136", "Create Account"],
    ["T1505", "Server Software Component"],
    ["T1098", "Account Manipulation"],
  ]],
  ["TA0004", "Privilege Escalation", [
    ["T1055", "Process Injection"],
    ["T1134", "Access Token Manipulation"],
    ["T1068", "Exploitation for Priv Esc"],
    ["T1548.002", "Bypass User Account Control"],
  ]],
  ["TA0005", "Defense Evasion", [
    ["T1027", "Obfuscated Files or Information"],
    ["T1036", "Masquerading"],
    ["T1562", "Impair Defenses"],
    ["T1070", "Indicator Removal"],
    ["T1218.011", "Rundll32"],
  ]],
  ["TA0006", "Credential Access", [
    ["T1110", "Brute Force"],
    ["T1003", "OS Credential Dumping"],
    ["T1555", "Credentials from Password Stores"],
    ["T1552", "Unsecured Credentials"],
    ["T1558", "Steal or Forge Kerberos Tickets"],
  ]],
  ["TA0007", "Discovery", [
    ["T1046", "Network Service Discovery"],
    ["T1082", "System Information Discovery"],
    ["T1087", "Account Discovery"],
    ["T1018", "Remote System Discovery"],
    ["T1069", "Permission Groups Discovery"],
  ]],
  ["TA0008", "Lateral Movement", [
    ["T1021", "Remote Services"],
    ["T1570", "Lateral Tool Transfer"],
    ["T1550", "Use Alternate Auth Material"],
    ["T1210", "Exploitation of Remote Services"],
  ]],
  ["TA0009", "Collection", [
    ["T1005", "Data from Local System"],
    ["T1114", "Email Collection"],
    ["T1560", "Archive Collected Data"],
    ["T1056", "Input Capture"],
  ]],
  ["TA0011", "Command & Control", [
    ["T1071", "Application Layer Protocol"],
    ["T1071.004", "DNS"],
    ["T1105", "Ingress Tool Transfer"],
    ["T1573", "Encrypted Channel"],
    ["T1090", "Proxy"],
    ["T1102", "Web Service"],
  ]],
  ["TA0010", "Exfiltration", [
    ["T1048", "Exfil Over Alternative Protocol"],
    ["T1041", "Exfiltration Over C2 Channel"],
    ["T1567", "Exfiltration Over Web Service"],
    ["T1020", "Automated Exfiltration"],
    ["T1537", "Transfer Data to Cloud Account"],
  ]],
  ["TA0040", "Impact", [
    ["T1486", "Data Encrypted for Impact"],
    ["T1490", "Inhibit System Recovery"],
    ["T1489", "Service Stop"],
    ["T1485", "Data Destruction"],
  ]],
];

export const COVERAGE_CATALOG: readonly CoverageTactic[] = RAW.map(
  ([id, name, techniques]) => ({
    id,
    name,
    techniques: techniques.map(([techniqueId, techniqueName]) => ({
      id: techniqueId,
      name: techniqueName,
      tier: tierFor(techniqueId),
    })),
  }),
);

export interface TierCounts {
  covered: number;
  partial: number;
  none: number;
  total: number;
}

export function countTiers(
  techniques: readonly CoverageTechnique[],
): TierCounts {
  const counts = { covered: 0, partial: 0, none: 0, total: techniques.length };
  for (const technique of techniques) counts[technique.tier] += 1;
  return counts;
}

export function catalogCounts(
  catalog: readonly CoverageTactic[] = COVERAGE_CATALOG,
): TierCounts {
  return countTiers(catalog.flatMap((tactic) => tactic.techniques));
}

export interface ObservedOverlay {
  byTechnique: ReadonlyMap<string, TechniqueCell>;
  uncatalogued: TechniqueCell[];
}

/** Keep observations grounded in backend ATT&CK assignments while making
 * catalogue drift visible instead of silently dropping newly mapped techniques. */
export function observedOverlay(
  findings: readonly AnomalyFindingOut[],
  catalog: readonly CoverageTactic[] = COVERAGE_CATALOG,
): ObservedOverlay {
  const catalogued = new Set(
    catalog.flatMap((tactic) => tactic.techniques.map((technique) => technique.id)),
  );
  const byTechnique = new Map<string, TechniqueCell>();
  const uncatalogued: TechniqueCell[] = [];

  for (const technique of buildTechniqueCells(findings)) {
    if (catalogued.has(technique.techniqueId)) {
      byTechnique.set(technique.techniqueId, technique);
    } else {
      uncatalogued.push(technique);
    }
  }

  return { byTechnique, uncatalogued };
}

/** Partial coverage counts half — the standard ATT&CK scoring convention. */
export function weightedCoverage({ covered, partial, total }: TierCounts): number {
  return total === 0 ? 0 : Math.round(((covered + 0.5 * partial) / total) * 100);
}

export function percent(part: number, whole: number): string {
  return whole === 0 ? "0%" : `${Math.round((part / whole) * 100)}%`;
}

export const TIER_LABEL: Record<CoverageTier, string> = {
  covered: "Covered",
  partial: "Partial",
  none: "None",
};

export const TIER_MEANING: Record<CoverageTier, string> = {
  covered: "Covered — a detector emits this technique",
  partial: "Partial — proxy signal exists, no detector",
  none: "None — no visibility from web-proxy logs",
};
