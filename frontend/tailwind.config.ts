import type { Config } from "tailwindcss";

import {
  ACCENT,
  ACCENT_HOVER,
  ACCENT_SOFT_BG,
  ACCENT_SOFT_BORDER,
  BORDER,
  BORDER_STRONG,
  CANVAS,
  DANGER,
  DIVIDER,
  ERROR,
  INK,
  SERIES,
  SEVERITY_HEX,
  SUCCESS,
  SURFACE,
  SURFACE_ALT,
} from "./lib/palette";

// Colours live in lib/palette.ts, not here: Recharts paints SVG and needs the
// literal hex, so a second copy in this file would be a drift waiting to happen.
const config: Config = {
  // `lib` and `hooks` are scanned too: the severity class names live in
  // lib/severity.ts, and Tailwind only emits classes it can see as literal text.
  // Leaving lib out silently drops `bg-sev-critical` and friends, which fails as
  // an invisible mark rather than as an error.
  content: [
    "./app/**/*.{ts,tsx}",
    "./components/**/*.{ts,tsx}",
    "./lib/**/*.{ts,tsx}",
    "./hooks/**/*.{ts,tsx}",
  ],
  theme: {
    extend: {
      fontFamily: {
        sans: ["var(--font-plex-sans)", "IBM Plex Sans", "sans-serif"],
        mono: ["var(--font-plex-mono)", "IBM Plex Mono", "monospace"],
      },
      colors: {
        canvas: CANVAS,
        surface: { DEFAULT: SURFACE, alt: SURFACE_ALT },
        accent: {
          DEFAULT: ACCENT,
          hover: ACCENT_HOVER,
          soft: ACCENT_SOFT_BG,
          "soft-border": ACCENT_SOFT_BORDER,
        },
        success: SUCCESS,
        danger: DANGER,
        ink: { ...INK },
        border: { DEFAULT: BORDER, strong: BORDER_STRONG },
        divider: DIVIDER,
        error: { ...ERROR },
        series: { ...SERIES },
        sev: { ...SEVERITY_HEX },
      },
      boxShadow: {
        card: "0 1px 3px rgba(16,24,40,0.06)",
        popover: "0 8px 24px rgba(16,24,40,0.12)",
        panel: "0 12px 40px rgba(16,24,40,0.18)",
        fab: "0 6px 20px rgba(47,111,235,0.35)",
      },
    },
  },
  plugins: [],
};

export default config;
