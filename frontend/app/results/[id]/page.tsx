"use client";

import { useParams, useRouter } from "next/navigation";
import { useEffect, useState } from "react";

import { getToken, getUpload, type UploadDetail } from "@/lib/api";

// Basic results view (Phase 3). Timeline, anomaly highlighting, and charts
// arrive in Phase 6.
export default function ResultsPage() {
  const params = useParams<{ id: string }>();
  const router = useRouter();
  const [data, setData] = useState<UploadDetail | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!getToken()) {
      router.replace("/login");
      return;
    }
    getUpload(Number(params.id))
      .then(setData)
      .catch((err) => setError(err instanceof Error ? err.message : "Failed"));
  }, [params.id, router]);

  if (error) {
    return (
      <main className="mx-auto max-w-4xl px-6 py-12">
        <p className="text-red-300">{error}</p>
      </main>
    );
  }
  if (!data) {
    return (
      <main className="mx-auto max-w-4xl px-6 py-12 text-slate-400">Loading…</main>
    );
  }

  return (
    <main className="mx-auto max-w-5xl px-6 py-10">
      <p className="text-sm font-medium uppercase tracking-widest text-accent">
        Analysis
      </p>
      <h1 className="mt-1 text-2xl font-semibold">{data.upload.filename}</h1>

      <div className="mt-6 grid grid-cols-2 gap-4 sm:grid-cols-3">
        <Stat label="Entries" value={data.summary.total_entries} />
        <Stat label="Flagged" value={data.summary.flagged_count} />
        <Stat label="Status" value={data.upload.status} />
      </div>

      <div className="mt-8 overflow-x-auto rounded-xl border border-slate-800">
        <table className="w-full text-left text-sm">
          <thead className="bg-panel text-slate-400">
            <tr>
              <Th>Time</Th>
              <Th>Src IP</Th>
              <Th>User</Th>
              <Th>URL</Th>
              <Th>Action</Th>
              <Th>Status</Th>
            </tr>
          </thead>
          <tbody>
            {data.entries.map((e) => (
              <tr key={e.id} className="border-t border-slate-800/70">
                <Td>{e.ts ? new Date(e.ts).toLocaleString() : "—"}</Td>
                <Td>{e.src_ip ?? "—"}</Td>
                <Td>{e.user ?? "—"}</Td>
                <Td className="max-w-xs truncate">{e.url ?? "—"}</Td>
                <Td>{e.action ?? "—"}</Td>
                <Td>{e.status_code ?? "—"}</Td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </main>
  );
}

function Stat({ label, value }: { label: string; value: string | number }) {
  return (
    <div className="rounded-xl border border-slate-800 bg-panel px-4 py-3">
      <div className="text-xs uppercase tracking-wide text-slate-500">{label}</div>
      <div className="mt-1 text-2xl font-semibold">{value}</div>
    </div>
  );
}

function Th({ children }: { children: React.ReactNode }) {
  return <th className="px-4 py-2.5 font-medium">{children}</th>;
}

function Td({
  children,
  className = "",
}: {
  children: React.ReactNode;
  className?: string;
}) {
  return <td className={`px-4 py-2.5 text-slate-300 ${className}`}>{children}</td>;
}