// The results view lives at /uploads/{id}/{tab}: each sub-view is its own path
// segment, so the URL is shareable, refresh-safe, and the detector-pie
// click-through ("open alerts") is a plain navigation.

export const RESULT_TABS = [
  "overview",
  "dashboard",
  "summary",
  "alerts",
  "threat-intel",
] as const;

export type ResultTab = (typeof RESULT_TABS)[number];

export const DEFAULT_TAB: ResultTab = "overview";

/** True when `raw` is a real tab segment. */
export function isResultTab(raw: string | null | undefined): raw is ResultTab {
  return RESULT_TABS.includes(raw as ResultTab);
}

/** Narrow an untrusted path segment to a real tab, defaulting to overview. */
export function tabFromParam(raw: string | null | undefined): ResultTab {
  return isResultTab(raw) ? (raw as ResultTab) : DEFAULT_TAB;
}

/**
 * Map a legacy `?tab=` value to its new path segment. `dashboard` collapses to
 * overview per the route migration; anything unknown or missing falls back to
 * overview too.
 */
export function legacyTabToPath(raw: string | null | undefined): ResultTab {
  if (raw === "dashboard") return DEFAULT_TAB;
  return tabFromParam(raw);
}
