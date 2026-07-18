import type { AnomalyFindingOut, LogEntryOut } from "./api";

// Tooltip enrichment derived from the currently-loaded entries page.
//
// The API's `timeline` and `top_talkers` carry counts only — not the source IPs
// per hour, the destinations per talker, or the IPs per detector. Rather than
// change the data contract, we reconstruct those breakdowns from the entries the
// table already holds. The cost: when the relevant entry isn't on the loaded
// page, the breakdown is empty and the tooltip says so. (A backend extension to
// `aggregates.py` would make these exact regardless of paging — noted in the
// handoff as the recommended follow-up.)

const MAX_ITEMS = 6;
export const NOT_LOADED = "(not on loaded page)";

interface AllowedBlocked {
  allowed: string[];
  blocked: string[];
}

export interface Breakdowns {
  /** Source IPs seen in each clock-hour bucket, split by action. Keyed by the
   *  hour-of-day (0–23), matching how the timeline buckets are compared. */
  hourIps: Map<number, AllowedBlocked>;
  /** Destinations each source IP talked to, split by action. */
  talkerDests: Map<string, AllowedBlocked>;
  /** Source IPs attributed to each detector `type`, via each finding's entry. */
  detectorIps: Map<string, string[]>;
}

function isBlocked(action: string | null): boolean {
  return (action ?? "").toLowerCase() === "blocked";
}

function hostOf(url: string): string {
  try {
    return new URL(url).host || url;
  } catch {
    return url;
  }
}

function take(set: Set<string>): string[] {
  return [...set].slice(0, MAX_ITEMS);
}

export function deriveBreakdowns(
  entries: readonly LogEntryOut[],
  findings: readonly AnomalyFindingOut[],
): Breakdowns {
  const entryIp = new Map<number, string | null>();
  const hourSets = new Map<number, { allowed: Set<string>; blocked: Set<string> }>();
  const destSets = new Map<string, { allowed: Set<string>; blocked: Set<string> }>();

  for (const entry of entries) {
    entryIp.set(entry.id, entry.src_ip);

    if (entry.ts && entry.src_ip) {
      const date = new Date(entry.ts);
      if (!Number.isNaN(date.getTime())) {
        const hour = date.getHours();
        const bucket =
          hourSets.get(hour) ?? { allowed: new Set(), blocked: new Set() };
        (isBlocked(entry.action) ? bucket.blocked : bucket.allowed).add(entry.src_ip);
        hourSets.set(hour, bucket);
      }
    }

    if (entry.src_ip && entry.url) {
      const dests =
        destSets.get(entry.src_ip) ?? { allowed: new Set(), blocked: new Set() };
      (isBlocked(entry.action) ? dests.blocked : dests.allowed).add(hostOf(entry.url));
      destSets.set(entry.src_ip, dests);
    }
  }

  const detectorSets = new Map<string, Set<string>>();
  for (const finding of findings) {
    if (finding.entry_id === null) continue;
    const ip = entryIp.get(finding.entry_id);
    if (!ip) continue;
    const set = detectorSets.get(finding.type) ?? new Set<string>();
    set.add(ip);
    detectorSets.set(finding.type, set);
  }

  const hourIps = new Map<number, AllowedBlocked>();
  for (const [hour, sets] of hourSets) {
    hourIps.set(hour, { allowed: take(sets.allowed), blocked: take(sets.blocked) });
  }

  const talkerDests = new Map<string, AllowedBlocked>();
  for (const [ip, sets] of destSets) {
    talkerDests.set(ip, { allowed: take(sets.allowed), blocked: take(sets.blocked) });
  }

  const detectorIps = new Map<string, string[]>();
  for (const [type, set] of detectorSets) {
    detectorIps.set(type, take(set));
  }

  return { hourIps, talkerDests, detectorIps };
}

/** A tooltip line list that falls back to the "(not on loaded page)" note when
 *  the breakdown came up empty. */
export function orNotLoaded(items: string[] | undefined): string[] {
  return items && items.length > 0 ? items : [NOT_LOADED];
}
