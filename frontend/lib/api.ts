// Central API base + fetch helper. Real endpoints wired in later phases.
export const API_BASE =
  process.env.NEXT_PUBLIC_API_BASE ?? "http://localhost:8000";

export function authHeaders(token: string): HeadersInit {
  return { Authorization: `Bearer ${token}` };
}
