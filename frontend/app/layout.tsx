import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "Tenex Log Analysis",
  description: "Upload logs, detect anomalies, review a SOC timeline.",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
