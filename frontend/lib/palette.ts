// Design tokens, in one place because they have two consumers that cannot share
// a class name: Tailwind (see tailwind.config.ts) and Recharts, which paints SVG
// and needs literal hex.
//
// Direction: a clean, light "SecOps" console — neutral light surfaces, one
// restrained blue accent, IBM Plex Sans for reading and IBM Plex Mono for data.

// ---- Surfaces & lines ----
export const CANVAS = "#f5f6f8"; // app background
export const SURFACE = "#ffffff"; // cards, header, table, inputs
export const SURFACE_ALT = "#f9fafb"; // table header, secondary hover
export const BORDER = "#e4e7ec"; // card/table borders, dividers
export const BORDER_STRONG = "#d0d5dd"; // inputs, secondary buttons
export const DIVIDER = "#eef0f3"; // row separators, meter tracks

// ---- Text ----
export const INK = {
  primary: "#1f2733", // headings, key values
  secondary: "#344054", // body copy, labels
  muted: "#667085", // sub-labels, secondary data
  faint: "#98a2b3", // captions, axis, disabled hints
  disabled: "#c1c7d0", // disabled controls
} as const;

// Tooltip body copy sits a step darker than muted for readability on white.
export const TOOLTIP_BODY = "#475467";

// ---- Accent (blue) ----
export const ACCENT = "#2f6feb";
export const ACCENT_HOVER = "#1f5fd6";
export const ACCENT_SOFT_BG = "#eef4ff"; // claude bubble, upload "+" chip
export const ACCENT_SOFT_BORDER = "#d6e4ff";

// ---- Semantic ----
export const SUCCESS = "#12a150"; // allowed traffic
export const DANGER = "#e5484d"; // blocked traffic

export const ERROR = {
  text: "#b42318",
  bg: "#fef3f2",
  border: "#fecdca",
} as const;

// ---- Severity ramp (findings, row dots, timeline, alert rails) ----
export const SEVERITY_HEX = {
  critical: "#d92d20",
  high: "#f79009",
  medium: "#eab308",
  low: "#667085",
} as const;

// ---- Chart series ----
export const SERIES = {
  allowed: SUCCESS,
  blocked: DANGER,
} as const;

// Detector-donut slice palette, cyclic. User-selectable — three presets.
export const PIE_PALETTES: readonly (readonly string[])[] = [
  ["#2f6feb", "#12a150", "#f79009", "#e5484d", "#98a2b3"],
  ["#1a73e8", "#34a853", "#fbbc04", "#ea4335", "#5f6368"],
  ["#2f6feb", "#7a5af8", "#12a150", "#f79009", "#98a2b3"],
] as const;

// Chart chrome sits one shade off the surface so the grid never competes with
// the data drawn on top of it.
export const CHART_INK = {
  grid: DIVIDER,
  axis: BORDER,
  label: INK.faint,
} as const;
