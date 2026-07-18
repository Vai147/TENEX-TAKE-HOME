"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";

import { ConsoleHeader } from "@/components/layout/ConsoleHeader";
import { ErrorBanner } from "@/components/ui/ErrorBanner";
import { login, setToken } from "@/lib/api";

export default function LoginPage() {
  const router = useRouter();
  const [username, setUsername] = useState("analyst");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setLoading(true);
    try {
      const token = await login(username, password);
      setToken(token);
      router.push("/upload");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Login failed");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="flex min-h-screen flex-col">
      <ConsoleHeader variant="login" />

      <main className="flex flex-1 items-center justify-center px-6 py-12">
        <div className="w-[400px] max-w-full rounded-xl border border-border bg-surface shadow-card">
          <form onSubmit={onSubmit} className="flex flex-col gap-[18px] p-8">
            <div>
              <p className="text-[12px] font-medium tracking-[0.02em] text-ink-muted">
                Sign in to continue
              </p>
              <h1 className="mt-1.5 text-[22px] font-semibold text-ink-primary">
                Tenex Console
              </h1>
            </div>

            <Field label="Username">
              <input
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                autoComplete="username"
                className={INPUT_CLASS}
              />
            </Field>

            <Field label="Password">
              <input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                autoComplete="current-password"
                className={INPUT_CLASS}
              />
            </Field>

            {error && <ErrorBanner>{error}</ErrorBanner>}

            <button
              type="submit"
              disabled={loading}
              className="mt-0.5 rounded-lg bg-accent py-2.5 text-[14px] font-semibold text-white transition-colors hover:bg-accent-hover disabled:opacity-70"
            >
              {loading ? "Signing in…" : "Sign in"}
            </button>
          </form>
        </div>
      </main>
    </div>
  );
}

const INPUT_CLASS =
  "rounded-lg border border-border-strong bg-surface px-3 py-2.5 text-[14px] text-ink-primary outline-none transition focus:border-accent focus:ring-4 focus:ring-accent/15";

function Field({
  label,
  children,
}: {
  label: string;
  children: React.ReactNode;
}) {
  return (
    <label className="flex flex-col gap-1.5">
      <span className="text-[12px] font-medium text-ink-secondary">{label}</span>
      {children}
    </label>
  );
}
