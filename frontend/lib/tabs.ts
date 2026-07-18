// The results view is a single route with four sub-views selected by `?tab=`.
// Keeping the tab in the URL makes it shareable and lets the detector-pie
// click-through ("open alerts") be a plain navigation.

export const RESULT_TABS = [
  "overview",
  "dashboard",
  "summary",
  "alerts",
  "threat-intel",
] as const;

export type ResultTab = (typeof RESULT_TABS)[number];

const DEFAULT_TAB: ResultTab = "overview";

/** Narrow an untrusted `?tab=` value to a real tab, defaulting to overview. */
export function tabFromQuery(raw: string | null): ResultTab {
  return RESULT_TABS.includes(raw as ResultTab) ? (raw as ResultTab) : DEFAULT_TAB;
}
