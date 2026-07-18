import type { LogEntryOut, Severity } from "@/lib/api";
import { formatNumber, formatTimestamp } from "@/lib/format";
import { SEVERITY_HEX } from "@/lib/palette";

interface EntriesTableProps {
  entries: readonly LogEntryOut[];
  /** Worst severity flagged against each entry id; absent means clean. */
  flagged: ReadonlyMap<number, Severity>;
  page: number;
  pageSize: number;
  totalEntries: number;
  loading: boolean;
  onPageChange: (page: number) => void;
}

export function EntriesTable({
  entries,
  flagged,
  page,
  pageSize,
  totalEntries,
  loading,
  onPageChange,
}: EntriesTableProps) {
  const lastPage = Math.max(1, Math.ceil(totalEntries / pageSize));
  // A hand-edited or stale `?page=` can point past the end. The container
  // rewrites the URL, but clamp here too so the counts never render a range
  // that does not exist ("showing 101–20 of 20").
  const current = Math.min(Math.max(1, page), lastPage);
  const first = totalEntries === 0 ? 0 : (current - 1) * pageSize + 1;
  const last = Math.min(current * pageSize, totalEntries);

  return (
    <section aria-labelledby="entries-heading">
      <header className="mb-3 flex flex-wrap items-baseline justify-between gap-2">
        <h2 id="entries-heading" className="text-[15px] font-semibold text-ink-primary">
          Log entries
        </h2>
        <p className="text-[12px] text-ink-faint">
          anomalous rows marked in the leftmost column
        </p>
      </header>

      <div className="overflow-x-auto rounded-[10px] border border-border bg-surface">
        {/* Hold the previous rows at reduced opacity while paging: a skeleton
            here would collapse the table height and jump the page. */}
        <table
          className={`w-full border-collapse font-mono text-[12px] transition-opacity ${loading ? "opacity-50" : ""}`}
        >
          <thead>
            <tr className="bg-surface-alt text-left text-ink-muted">
              <th className="w-6 px-3.5 py-[11px]">
                <span className="sr-only">Anomaly</span>
              </th>
              <Th>Time</Th>
              <Th>Src IP</Th>
              <Th>User</Th>
              <Th>URL</Th>
              <Th>Action</Th>
              <Th className="text-right">Status</Th>
              <Th className="text-right">Bytes</Th>
            </tr>
          </thead>
          <tbody>
            {entries.map((entry) => (
              <Row key={entry.id} entry={entry} severity={flagged.get(entry.id)} />
            ))}
          </tbody>
        </table>

        {entries.length === 0 && !loading && (
          <p className="px-3.5 py-8 text-center text-[13px] text-ink-muted">
            No entries on this page.
          </p>
        )}
      </div>

      <nav
        aria-label="Entries pagination"
        className="mt-2.5 flex flex-wrap items-center justify-between gap-3"
      >
        <p className="font-mono text-[12px] text-ink-faint">
          showing {formatNumber(first)}–{formatNumber(last)} of{" "}
          {formatNumber(totalEntries)}
        </p>
        <div className="flex items-center gap-2">
          <PageButton onClick={() => onPageChange(current - 1)} disabled={current <= 1}>
            Prev
          </PageButton>
          <span className="font-mono text-[12px] text-ink-muted">
            {current} / {lastPage}
          </span>
          <PageButton onClick={() => onPageChange(current + 1)} disabled={current >= lastPage}>
            Next
          </PageButton>
        </div>
      </nav>
    </section>
  );
}

function Row({ entry, severity }: { entry: LogEntryOut; severity: Severity | undefined }) {
  const blocked = (entry.action ?? "").toLowerCase() === "blocked";
  return (
    <tr
      className="border-t border-divider"
      style={severity ? { background: "rgba(217,45,32,0.05)" } : undefined}
    >
      <td className="px-3.5 py-2.5 align-middle">
        {severity && (
          <span
            className="block h-1.5 w-1.5 rounded-full"
            style={{ background: SEVERITY_HEX[severity] }}
          >
            <span className="sr-only">{severity} severity anomaly</span>
          </span>
        )}
      </td>
      <Td className="whitespace-nowrap text-ink-muted">{formatTimestamp(entry.ts)}</Td>
      <Td className="whitespace-nowrap text-ink-primary">{entry.src_ip ?? "—"}</Td>
      <Td className="text-ink-muted">{entry.user ?? "—"}</Td>
      <Td
        className="max-w-[280px] truncate text-ink-muted"
        title={entry.url ?? undefined}
      >
        {entry.url ?? "—"}
      </Td>
      <Td className={blocked ? "text-danger" : "text-ink-muted"}>
        {entry.action ?? "—"}
      </Td>
      <Td className="text-right text-ink-primary">{entry.status_code ?? "—"}</Td>
      <Td className="text-right text-ink-primary">
        {entry.bytes_recv === null ? "—" : formatNumber(entry.bytes_recv)}
      </Td>
    </tr>
  );
}

function Th({ children, className = "" }: { children: React.ReactNode; className?: string }) {
  return (
    <th className={`px-3.5 py-[11px] font-sans font-medium ${className}`}>{children}</th>
  );
}

function Td({
  children,
  className = "",
  title,
}: {
  children: React.ReactNode;
  className?: string;
  title?: string;
}) {
  return (
    <td className={`px-3.5 py-2.5 ${className}`} title={title}>
      {children}
    </td>
  );
}

function PageButton({
  children,
  onClick,
  disabled,
}: {
  children: React.ReactNode;
  onClick: () => void;
  disabled: boolean;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      disabled={disabled}
      className="rounded-md border border-border-strong bg-surface px-3.5 py-1.5 text-[12px] font-medium text-ink-secondary transition-colors hover:border-ink-faint focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-accent disabled:cursor-not-allowed disabled:text-ink-disabled disabled:hover:border-border-strong"
    >
      {children}
    </button>
  );
}
