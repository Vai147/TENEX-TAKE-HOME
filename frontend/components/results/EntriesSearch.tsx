"use client";

import { Search, X } from "lucide-react";
import { useEffect, useRef, useState } from "react";

import { Input } from "@/components/ui/input";
import { formatNumber } from "@/lib/format";

interface EntriesSearchProps {
  /** The active term from the URL — the source of truth. */
  value: string;
  onSearch: (q: string) => void;
  /** Filtered row count, shown when a search is active. */
  resultCount: number;
  loading: boolean;
}

const DEBOUNCE_MS = 300;

export function EntriesSearch({ value, onSearch, resultCount, loading }: EntriesSearchProps) {
  const [local, setLocal] = useState(value);
  // The last term we pushed to the URL. Lets us tell our own round-trips from
  // external URL changes (back/forward, cleared elsewhere).
  const lastPushed = useRef(value);

  useEffect(() => {
    if (value !== lastPushed.current) {
      lastPushed.current = value;
      setLocal(value);
    }
  }, [value]);

  useEffect(() => {
    if (local === lastPushed.current) return;
    const timer = setTimeout(() => {
      lastPushed.current = local;
      onSearch(local);
    }, DEBOUNCE_MS);
    return () => clearTimeout(timer);
  }, [local, onSearch]);

  const active = value.trim().length > 0;

  return (
    <div className="mb-3 flex flex-wrap items-center gap-x-3 gap-y-1.5">
      <div className="relative w-full max-w-[360px]">
        <Search
          className="pointer-events-none absolute left-2.5 top-1/2 size-4 -translate-y-1/2 text-muted-foreground"
          aria-hidden="true"
        />
        <Input
          type="search"
          value={local}
          onChange={(e) => setLocal(e.target.value)}
          placeholder="Search by IP, user, URL, action…"
          aria-label="Search log entries"
          className="h-9 pl-8 pr-8"
        />
        {local && (
          <button
            type="button"
            onClick={() => setLocal("")}
            aria-label="Clear search"
            className="absolute right-2 top-1/2 -translate-y-1/2 text-muted-foreground transition-colors hover:text-foreground"
          >
            <X className="size-4" />
          </button>
        )}
      </div>

      {active && (
        <span className="font-mono text-xs text-muted-foreground" aria-live="polite">
          {loading
            ? "searching…"
            : `${formatNumber(resultCount)} match${resultCount === 1 ? "" : "es"}`}
        </span>
      )}
    </div>
  );
}
