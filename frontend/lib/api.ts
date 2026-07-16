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

export interface UploadDetail {
  upload: UploadOut;
  summary: { total_entries: number; flagged_count: number };
  entries: LogEntryOut[];
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

export async function getUpload(id: number): Promise<UploadDetail> {
  return authedJson<UploadDetail>(`/api/uploads/${id}`);
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
