import { Button } from "@/components/ui/button";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
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
        <h2 id="entries-heading" className="text-[15px] font-semibold text-foreground">
          Log entries
        </h2>
        <p className="text-xs text-muted-foreground">
          anomalous rows marked in the leftmost column
        </p>
      </header>

      <div className="overflow-x-auto rounded-xl border bg-card">
        {/* Hold the previous rows at reduced opacity while paging: a skeleton
            here would collapse the table height and jump the page. */}
        <Table
          className={`font-mono text-xs transition-opacity ${loading ? "opacity-50" : ""}`}
        >
          <TableHeader>
            <TableRow className="bg-muted/40 hover:bg-muted/40">
              <TableHead className="w-6">
                <span className="sr-only">Anomaly</span>
              </TableHead>
              <TableHead className="font-sans">Time</TableHead>
              <TableHead className="font-sans">Src IP</TableHead>
              <TableHead className="font-sans">User</TableHead>
              <TableHead className="font-sans">URL</TableHead>
              <TableHead className="font-sans">Action</TableHead>
              <TableHead className="text-right font-sans">Status</TableHead>
              <TableHead className="text-right font-sans">Bytes</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {entries.map((entry) => (
              <Row key={entry.id} entry={entry} severity={flagged.get(entry.id)} />
            ))}
          </TableBody>
        </Table>

        {entries.length === 0 && !loading && (
          <p className="px-4 py-8 text-center text-[13px] text-muted-foreground">
            No entries on this page.
          </p>
        )}
      </div>

      <nav
        aria-label="Entries pagination"
        className="mt-2.5 flex flex-wrap items-center justify-between gap-3"
      >
        <p className="font-mono text-xs text-muted-foreground">
          showing {formatNumber(first)}–{formatNumber(last)} of{" "}
          {formatNumber(totalEntries)}
        </p>
        <div className="flex items-center gap-2">
          <Button
            variant="outline"
            size="sm"
            onClick={() => onPageChange(current - 1)}
            disabled={current <= 1}
          >
            Prev
          </Button>
          <span className="font-mono text-xs text-muted-foreground">
            {current} / {lastPage}
          </span>
          <Button
            variant="outline"
            size="sm"
            onClick={() => onPageChange(current + 1)}
            disabled={current >= lastPage}
          >
            Next
          </Button>
        </div>
      </nav>
    </section>
  );
}

function Row({ entry, severity }: { entry: LogEntryOut; severity: Severity | undefined }) {
  const blocked = (entry.action ?? "").toLowerCase() === "blocked";
  return (
    <TableRow className={severity ? "bg-destructive/[0.05] hover:bg-destructive/[0.08]" : undefined}>
      <TableCell className="align-middle">
        {severity && (
          <span
            className="block h-1.5 w-1.5 rounded-full"
            style={{ background: SEVERITY_HEX[severity] }}
          >
            <span className="sr-only">{severity} severity anomaly</span>
          </span>
        )}
      </TableCell>
      <TableCell className="whitespace-nowrap text-muted-foreground">
        {formatTimestamp(entry.ts)}
      </TableCell>
      <TableCell className="whitespace-nowrap text-foreground">{entry.src_ip ?? "—"}</TableCell>
      <TableCell className="text-muted-foreground">{entry.user ?? "—"}</TableCell>
      <TableCell className="max-w-[280px] truncate text-muted-foreground" title={entry.url ?? undefined}>
        {entry.url ?? "—"}
      </TableCell>
      <TableCell className={blocked ? "font-medium text-danger" : "text-muted-foreground"}>
        {entry.action ?? "—"}
      </TableCell>
      <TableCell className="text-right text-foreground">{entry.status_code ?? "—"}</TableCell>
      <TableCell className="text-right text-foreground">
        {entry.bytes_recv === null ? "—" : formatNumber(entry.bytes_recv)}
      </TableCell>
    </TableRow>
  );
}
