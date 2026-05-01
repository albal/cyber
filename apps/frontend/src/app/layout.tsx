import type { Metadata } from "next";
import Link from "next/link";
import "./globals.css";

export const metadata: Metadata = {
  title: "Cyberscan",
  description: "OSS-only web vulnerability scanner",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>
        <header className="border-b border-border bg-panel">
          <div className="mx-auto max-w-6xl px-6 py-4 flex items-center justify-between">
            <Link href="/" className="font-semibold text-accent">
              cyberscan
            </Link>
            <nav className="flex gap-4 text-sm text-gray-300">
              <Link href="/assets">Assets</Link>
              <Link href="/scans">Scans</Link>
              <Link href="/login" className="text-gray-500">
                Login
              </Link>
            </nav>
          </div>
        </header>
        <main className="mx-auto max-w-6xl px-6 py-8">{children}</main>
      </body>
    </html>
  );
}
