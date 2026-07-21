"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";

import { Button } from "@/components/ui/button";
import { ThemeToggle } from "@/components/ui/ThemeToggle";
import { clearToken } from "@/lib/api";
import { RESULT_TABS, type ResultTab } from "@/lib/tabs";

const TAB_LABELS: Record<ResultTab, string> = {
  overview: "Overview",
  dashboard: "Dashboard",
  summary: "Summary",
  alerts: "Alerts",
  "threat-intel": "Threat Intel",
  coverage: "MITRE Dashboard",
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
    <header className="border-b bg-card text-card-foreground">
      <div className="flex h-14 items-center gap-4 px-7">
        <Logo href={logoHref} />

        <div className="ml-auto flex items-center gap-3">
          {variant === "app" && (
            <>
              <span className="text-[13px] text-muted-foreground">analyst@tenex</span>
              <Button variant="outline" size="sm" onClick={logout}>
                Log out
              </Button>
            </>
          )}
          <ThemeToggle />
        </div>
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
      <span className="inline-flex h-6 w-6 items-center justify-center rounded-md bg-accent text-[13px] font-bold text-accent-foreground dark:bg-[#1d4ed8]">
        T
      </span>
      <span className="text-[15px] font-semibold tracking-[0.01em] text-foreground">
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
      <Link
        href="/upload"
        className="-mb-px mr-1 border-b-2 border-transparent px-3.5 py-3 text-[13px] font-medium text-muted-foreground transition-colors hover:text-foreground"
      >
        New upload
      </Link>
      <span className="my-2.5 mr-1 w-px bg-border" aria-hidden="true" />
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
                : "border-transparent text-muted-foreground hover:text-foreground"
            }`}
          >
            {TAB_LABELS[tab]}
          </Link>
        );
      })}
    </nav>
  );
}
