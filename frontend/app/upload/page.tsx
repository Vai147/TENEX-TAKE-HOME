"use client";

import { useRouter } from "next/navigation";
import { useEffect, useState } from "react";

import { AskClaude } from "@/components/chat/AskClaude";
import { ConsoleHeader } from "@/components/layout/ConsoleHeader";
import { ErrorBanner } from "@/components/ui/ErrorBanner";
import { getToken, uploadFile } from "@/lib/api";

export default function UploadPage() {
  const router = useRouter();
  const [file, setFile] = useState<File | null>(null);
  const [dragOver, setDragOver] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  // Guard: bounce to login if no token.
  useEffect(() => {
    if (!getToken()) router.replace("/login");
  }, [router]);

  async function submit() {
    if (!file) return;
    setError(null);
    setLoading(true);
    try {
      const upload = await uploadFile(file);
      router.push(`/uploads/${upload.id}/overview`);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Upload failed");
      setLoading(false);
    }
  }

  const zoneActive = dragOver || file !== null;

  return (
    <div className="flex min-h-screen flex-col">
      <ConsoleHeader variant="app" />

      <main className="flex flex-1 items-center justify-center px-6 py-12">
        <div className="flex w-[560px] max-w-full flex-col gap-4">
          <div>
            <p className="text-[12px] font-medium text-ink-muted">Ingest</p>
            <h1 className="mt-1 text-[22px] font-semibold text-ink-primary">
              Upload a log file
            </h1>
          </div>

          <label
            onDragOver={(e) => {
              e.preventDefault();
              setDragOver(true);
            }}
            onDragLeave={() => setDragOver(false)}
            onDrop={(e) => {
              e.preventDefault();
              setDragOver(false);
              const dropped = e.dataTransfer.files?.[0];
              if (dropped) {
                setFile(dropped);
                setError(null);
              }
            }}
            className={`flex cursor-pointer flex-col items-center gap-3 rounded-xl border border-dashed px-6 py-[52px] text-center transition-colors hover:border-accent hover:bg-[#fbfcff] ${
              zoneActive ? "border-accent bg-[#fbfcff]" : "border-border-strong bg-surface"
            }`}
          >
            <input
              type="file"
              accept=".log,.txt,.csv"
              className="hidden"
              onChange={(e) => {
                setFile(e.target.files?.[0] ?? null);
                setError(null);
              }}
            />
            <span
              className="inline-flex h-11 w-11 items-center justify-center rounded-full bg-accent-soft text-[26px] font-normal leading-none text-accent"
              aria-hidden="true"
            >
              +
            </span>
            <span className="text-[14px] text-ink-secondary">
              {file ? file.name : "Drag a log file here, or click to browse"}
            </span>
            <span className="font-mono text-[12px] text-ink-faint">
              .log · .txt · .csv
            </span>
          </label>

          {error && <ErrorBanner>{error}</ErrorBanner>}

          <button
            onClick={submit}
            disabled={!file || loading}
            className={`rounded-lg py-3 text-[14px] font-semibold text-white transition-colors ${
              file ? "bg-accent hover:bg-accent-hover" : "bg-ink-disabled"
            } disabled:cursor-not-allowed`}
          >
            {loading ? "Analyzing…" : "Upload & analyze"}
          </button>
        </div>
      </main>

      <AskClaude />
    </div>
  );
}
