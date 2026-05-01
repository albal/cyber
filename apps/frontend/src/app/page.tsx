import Link from "next/link";

export default function Home() {
  return (
    <div className="space-y-6">
      <section className="rounded-lg border border-border bg-panel p-8">
        <h1 className="text-3xl font-semibold mb-2">cyberscan</h1>
        <p className="text-gray-400 max-w-2xl">
          Paste a URL, prove you own it, get a prioritized list of findings — CVE-enriched,
          KEV-flagged, with remediation. OSS scanners (Naabu, httpx, Nuclei) under the hood.
        </p>
        <div className="mt-6 flex gap-3">
          <Link
            href="/assets"
            className="rounded bg-accent text-black px-4 py-2 text-sm font-semibold"
          >
            New asset
          </Link>
          <Link
            href="/scans"
            className="rounded border border-border px-4 py-2 text-sm"
          >
            View scans
          </Link>
        </div>
      </section>

      <section className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <Card title="1. Add asset" body="Add a website you own. We mint a verification token." />
        <Card title="2. Verify" body="Drop a file at /.well-known/, click Verify." />
        <Card title="3. Scan" body="Findings appear within minutes, prioritized by KEV + CVSS." />
      </section>
    </div>
  );
}

function Card({ title, body }: { title: string; body: string }) {
  return (
    <div className="rounded-lg border border-border bg-panel p-5">
      <h3 className="font-semibold mb-1">{title}</h3>
      <p className="text-sm text-gray-400">{body}</p>
    </div>
  );
}
