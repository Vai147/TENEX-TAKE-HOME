"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";

import { clearToken } from "@/lib/api";
import { RESULT_TABS, type ResultTab } from "@/lib/tabs";

const TAB_LABELS: Record<ResultTab, string> = {
  overview: "Overview",
  dashboard: "Dashboard",
  summary: "Summary",
  alerts: "Alerts",
  "threat-intel": "Threat Intel",
};

interface ConsoleHeaderProps {
  /** "login" hides the logged-in chrome; "app" shows logout (+ tabs when an
   *  upload is in context). */
  variant: "login" | "app";
  /** Present on the results route: enables the tab nav and points the logo back
   *  at the overview. */
  uploadId?: number;
  activeTab?: ResultTab;
}

export function ConsoleHeader({ variant, uploadId, activeTab }: ConsoleHeaderProps) {
  const router = useRouter();

  function logout() {
    clearToken();
    router.push("/login");
  }

  const logoHref =
    variant === "login"
      ? undefined
      : uploadId !== undefined
        ? `/uploads/${uploadId}/overview`
        : "/upload";

  return (
    <header className="border-b border-border bg-surface">
      <div className="flex h-14 items-center gap-4 px-7">
        <Logo href={logoHref} />

        {variant === "app" && (
          <span className="ml-auto inline-flex items-center gap-3.5">
            <span className="text-[13px] text-ink-muted">analyst@tenex</span>
            <button
              type="button"
              onClick={logout}
              className="rounded-md border border-border-strong px-3 py-1.5 text-[12px] font-medium text-ink-secondary transition-colors hover:border-ink-faint hover:bg-canvas"
            >
              Log out
            </button>
          </span>
        )}
      </div>

      {variant === "app" && uploadId !== undefined && (
        <TabNav uploadId={uploadId} activeTab={activeTab ?? "overview"} />
      )}
    </header>
  );
}

function Logo({ href }: { href?: string }) {
  const inner = (
    <>
      <span className="inline-flex h-6 w-6 items-center justify-center rounded-md bg-accent text-[13px] font-bold text-white">
        T
      </span>
      <span className="text-[15px] font-semibold tracking-[0.01em] text-ink-primary">
        Tenex Console
      </span>
    </>
  );

  const box = "inline-flex items-center gap-2.5";

  if (!href) {
    return (
      <span className={box} aria-label="Tenex Console">
        {inner}
      </span>
    );
  }
  return (
    <Link href={href} className={box} aria-label="Tenex Console — go to overview">
      {inner}
    </Link>
  );
}

function TabNav({
  uploadId,
  activeTab,
}: {
  uploadId: number;
  activeTab: ResultTab;
}) {
  return (
    <nav aria-label="Results views" className="flex gap-0.5 px-5">
      {RESULT_TABS.map((tab) => {
        const active = tab === activeTab;
        return (
          <Link
            key={tab}
            href={`/uploads/${uploadId}/${tab}`}
            scroll={false}
            aria-current={active ? "page" : undefined}
            className={`-mb-px border-b-2 px-3.5 py-3 text-[13px] font-medium transition-colors ${
              active
                ? "border-accent text-accent"
                : "border-transparent text-ink-secondary hover:text-ink-primary"
            }`}
          >
            {TAB_LABELS[tab]}
          </Link>
        );
      })}
    </nav>
  );
}
