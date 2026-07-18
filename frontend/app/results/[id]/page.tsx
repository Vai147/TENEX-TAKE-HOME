import { redirect } from "next/navigation";

import { legacyTabToPath } from "@/lib/tabs";

// Backward-compatible redirect for the old query-param routes:
//   /results/{id}?tab=alerts  ->  /uploads/{id}/alerts
// `tab=dashboard` collapses to overview. Runs on the server so direct
// navigation and refresh land on the new URL immediately. The `page` param is
// carried over so a deep-linked, paginated table survives the move.
export default async function LegacyResultsRedirect({
  params,
  searchParams,
}: {
  params: Promise<{ id: string }>;
  searchParams: Promise<{ [key: string]: string | string[] | undefined }>;
}) {
  const { id } = await params;
  const sp = await searchParams;

  const rawTab = typeof sp.tab === "string" ? sp.tab : null;
  const tab = legacyTabToPath(rawTab);

  const rawPage = typeof sp.page === "string" ? sp.page : null;
  const suffix = rawPage && rawPage !== "1" ? `?page=${rawPage}` : "";

  redirect(`/uploads/${id}/${tab}${suffix}`);
}
