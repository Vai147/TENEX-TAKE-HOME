import Link from "next/link";

export default function Home() {
  return (
    <main className="mx-auto flex min-h-screen max-w-3xl flex-col justify-center px-6">
      <p className="mb-3 text-sm font-medium uppercase tracking-widest text-accent">
        Tenex · SOC Log Analysis
      </p>
      <h1 className="text-4xl font-semibold leading-tight md:text-5xl">
        Upload a log. Get a timeline, anomalies, and confidence scores.
      </h1>
      <p className="mt-4 max-w-xl text-slate-400">
        Deterministic detectors flag unusual activity; Claude summarizes the
        events for a SOC analyst. Prototype build.
      </p>
      <div className="mt-8 flex gap-4">
        <Link
          href="/login"
          className="rounded-lg bg-accent px-5 py-2.5 font-medium text-surface transition hover:opacity-90"
        >
          Log in
        </Link>
      </div>
    </main>
  );
}
