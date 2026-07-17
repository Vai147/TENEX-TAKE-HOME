// Central API base + auth helpers.
export const API_BASE =
  process.env.NEXT_PUBLIC_API_BASE ?? "http://localhost:8000";

const TOKEN_KEY = "tenex_token";

export function authHeaders(token: string): HeadersInit {
  return { Authorization: `Bearer ${token}` };
}

export function getToken(): string | null {
  if (typeof window === "undefined") return null;
  return window.localStorage.getItem(TOKEN_KEY);
}

export function setToken(token: string): void {
  window.localStorage.setItem(TOKEN_KEY, token);
}

export function clearToken(): void {
  window.localStorage.removeItem(TOKEN_KEY);
}

// ---- Types mirroring backend schemas ----
export interface UploadOut {
  id: number;
  filename: string;
  status: string;
  llm_ok: boolean;
  created_at: string;
}

export interface LogEntryOut {
  id: number;
  ts: string | null;
  src_ip: string | null;
  user: string | null;
  url: string | null;
  action: string | null;
  status_code: number | null;
  bytes_sent: number | null;
  bytes_recv: number | null;
  user_agent: string | null;
}

export interface AnomalyFindingOut {
  id: number;
  entry_id: number | null;
  type: string;
  confidence: number;
  severity: Severity;
  reason: string;
  source: string;
  // Claude's annotations. Null when the LLM layer fell back; `severity` above is
  // always the deterministic engine's verdict and is never overwritten.
  explanation: string | null;
  llm_severity: Severity | null;
}

export type Severity = "low" | "medium" | "high" | "critical";

export interface TimelineBucket {
  start: string;
  requests: number;
  blocked: number;
}

export interface TalkerStat {
  src_ip: string;
  requests: number;
  blocked: number;
  bytes_recv: number;
  bytes_sent: number;
}

export interface UploadDetail {
  upload: UploadOut;
  summary: { total_entries: number; flagged_count: number; narrative: string | null };
  entries: LogEntryOut[];
  findings: AnomalyFindingOut[];
}

export interface AnomaliesOut {
  upload_id: number;
  // False means `narrative` came from the deterministic fallback and every
  // `explanation` is null. The findings themselves are unaffected either way.
  llm_ok: boolean;
  narrative: string | null;
  flagged_count: number;
  total_entries: number;
  findings: AnomalyFindingOut[];
  timeline: TimelineBucket[];
  top_talkers: TalkerStat[];
}

async function authedJson<T>(path: string, init?: RequestInit): Promise<T> {
  const token = getToken();
  if (!token) throw new Error("Not authenticated");
  const res = await fetch(`${API_BASE}${path}`, {
    ...init,
    headers: { ...(init?.headers ?? {}), ...authHeaders(token) },
  });
  if (res.status === 401) {
    clearToken();
    throw new Error("Session expired");
  }
  if (!res.ok) {
    const detail = await res.json().catch(() => ({}));
    throw new Error(detail.detail ?? `Request failed (${res.status})`);
  }
  return (await res.json()) as T;
}

// Upload a log file (multipart). Returns the created upload row.
export async function uploadFile(file: File): Promise<UploadOut> {
  const form = new FormData();
  form.append("file", file);
  return authedJson<UploadOut>("/api/uploads", { method: "POST", body: form });
}

export async function getUpload(
  id: number,
  { limit, offset }: { limit?: number; offset?: number } = {},
): Promise<UploadDetail> {
  const params = new URLSearchParams();
  if (limit !== undefined) params.set("limit", String(limit));
  if (offset !== undefined) params.set("offset", String(offset));
  const query = params.toString();
  return authedJson<UploadDetail>(
    `/api/uploads/${id}${query ? `?${query}` : ""}`,
  );
}

// The analysis view: findings, narrative and chart data, without the entries table.
export async function getAnomalies(id: number): Promise<AnomaliesOut> {
  return authedJson<AnomaliesOut>(`/api/uploads/${id}/anomalies`);
}

// Exchange username/password for a JWT. Backend expects OAuth2 form encoding.
export async function login(
  username: string,
  password: string,
): Promise<string> {
  const body = new URLSearchParams({ username, password });
  const res = await fetch(`${API_BASE}/api/auth/login`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body,
  });
  if (!res.ok) {
    const detail = await res.json().catch(() => ({}));
    throw new Error(detail.detail ?? "Login failed");
  }
  const data = (await res.json()) as { access_token: string };
  return data.access_token;
}
