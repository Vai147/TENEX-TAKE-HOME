"use client";

import { useRouter } from "next/navigation";
import { useEffect, useState } from "react";

import { AskClaude } from "@/components/chat/AskClaude";
import { ConsoleHeader } from "@/components/layout/ConsoleHeader";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
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
    <div className="flex min-h-screen flex-col bg-background text-foreground">
      <ConsoleHeader variant="app" />

      <main className="flex flex-1 items-center justify-center px-6 py-12">
        <div className="flex w-[560px] max-w-full flex-col gap-4">
          <div>
            <p className="text-xs font-medium uppercase tracking-[0.06em] text-muted-foreground">
              Ingest
            </p>
            <h1 className="mt-1 text-2xl font-semibold tracking-tight">
              Upload a log file
            </h1>
          </div>

          <Card>
            <CardContent className="flex flex-col gap-4">
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
                className={`flex cursor-pointer flex-col items-center gap-3 rounded-lg border border-dashed px-6 py-[52px] text-center transition-colors hover:border-accent hover:bg-accent/5 ${
                  zoneActive ? "border-accent bg-accent/5" : "border-border-strong bg-muted/30"
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
                <span className="text-sm text-foreground">
                  {file ? file.name : "Drag a log file here, or click to browse"}
                </span>
                <span className="font-mono text-xs text-muted-foreground">
                  .log · .txt · .csv
                </span>
              </label>

              {error && <ErrorBanner>{error}</ErrorBanner>}

              <Button
                onClick={submit}
                disabled={!file || loading}
                className="w-full"
                size="lg"
              >
                {loading ? "Analyzing…" : "Upload & analyze"}
              </Button>
            </CardContent>
          </Card>
        </div>
      </main>

      <AskClaude />
    </div>
  );
}
