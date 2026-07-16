"use client";

import { useRouter } from "next/navigation";
import { useEffect, useState } from "react";

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
      router.push(`/results/${upload.id}`);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Upload failed");
      setLoading(false);
    }
  }

  return (
    <main className="mx-auto flex min-h-screen max-w-2xl flex-col justify-center px-6">
      <p className="mb-2 text-sm font-medium uppercase tracking-widest text-accent">
        Tenex · SOC
      </p>
      <h1 className="mb-6 text-3xl font-semibold">Upload a log file</h1>

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
          if (dropped) setFile(dropped);
        }}
        className={`flex cursor-pointer flex-col items-center justify-center rounded-xl border-2 border-dashed px-6 py-14 text-center transition ${
          dragOver ? "border-accent bg-panel" : "border-slate-700 bg-panel/50"
        }`}
      >
        <input
          type="file"
          accept=".log,.txt,.csv"
          className="hidden"
          onChange={(e) => setFile(e.target.files?.[0] ?? null)}
        />
        <span className="text-slate-300">
          {file ? file.name : "Drag a .log / .txt / .csv file here, or click to browse"}
        </span>
        {file && (
          <span className="mt-1 text-xs text-slate-500">
            {(file.size / 1024).toFixed(1)} KB
          </span>
        )}
      </label>

      {error && (
        <p className="mt-4 rounded-lg bg-red-950/60 px-3 py-2 text-sm text-red-300">
          {error}
        </p>
      )}

      <button
        onClick={submit}
        disabled={!file || loading}
        className="mt-6 rounded-lg bg-accent px-5 py-2.5 font-medium text-surface transition hover:opacity-90 disabled:opacity-40"
      >
        {loading ? "Analyzing…" : "Upload & analyze"}
      </button>
    </main>
  );
}