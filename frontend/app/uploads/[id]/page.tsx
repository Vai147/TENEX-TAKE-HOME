import { redirect } from "next/navigation";

import { DEFAULT_TAB } from "@/lib/tabs";

// Bare /uploads/{id} has no view of its own — send it to the default tab.
export default async function UploadIndex({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  const { id } = await params;
  redirect(`/uploads/${id}/${DEFAULT_TAB}`);
}
