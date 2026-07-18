/** The console's one error surface: red-on-pink, shared by login, upload, and the
 *  results load path so a failure always reads the same. */
export function ErrorBanner({ children }: { children: React.ReactNode }) {
  return (
    <p
      role="alert"
      className="rounded-lg border border-error-border bg-error-bg px-3 py-2.5 text-[12px] leading-relaxed text-error-text"
    >
      {children}
    </p>
  );
}
