const DETECTOR_LABELS: Record<string, string> = {
  ip_burst: "IP burst",
  blocked_spike: "Blocked spike",
  rare_user_agent: "Rare user agent",
  byte_volume: "Byte volume",
  off_hours: "Off-hours access",
};

/** A detector's `type` as an analyst should read it. An unknown type is
 *  prettified rather than dropped, so a new backend detector still surfaces
 *  legibly without waiting on a frontend release. */
export function detectorLabel(type: string): string {
  return DETECTOR_LABELS[type] ?? type.replace(/_/g, " ");
}

const BYTE_UNITS = ["B", "KB", "MB", "GB", "TB"] as const;

export function formatBytes(bytes: number): string {
  if (bytes <= 0) return "0 B";
  const exponent = Math.min(
    Math.floor(Math.log(bytes) / Math.log(1024)),
    BYTE_UNITS.length - 1,
  );
  const value = bytes / 1024 ** exponent;
  const rounded = value >= 100 || exponent === 0 ? Math.round(value) : value.toFixed(1);
  return `${rounded} ${BYTE_UNITS[exponent]}`;
}

export function formatNumber(value: number): string {
  return value.toLocaleString();
}

export function formatTimestamp(iso: string | null): string {
  if (!iso) return "—";
  const date = new Date(iso);
  return Number.isNaN(date.getTime()) ? "—" : date.toLocaleString();
}

/** Hour-bucket axis ticks. The full timestamp stays in the tooltip, so this can
 *  afford to be short. */
export function formatHour(iso: string): string {
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return iso;
  return date.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
}
