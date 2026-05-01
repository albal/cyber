"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import { api, type Asset } from "@/lib/api";

export default function AssetsPage() {
  const [assets, setAssets] = useState<Asset[] | null>(null);
  const [name, setName] = useState("");
  const [url, setUrl] = useState("http://juice-shop:3000");
  const [err, setErr] = useState<string | null>(null);

  async function load() {
    try {
      setAssets(await api<Asset[]>("/api/v1/assets"));
    } catch (e) {
      setErr(e instanceof Error ? e.message : "failed");
    }
  }

  useEffect(() => {
    void load();
  }, []);

  async function create(e: React.FormEvent) {
    e.preventDefault();
    setErr(null);
    try {
      await api<Asset>("/api/v1/assets", {
        method: "POST",
        body: JSON.stringify({ name, target_url: url, verification_method: "http_file" }),
      });
      setName("");
      void load();
    } catch (e) {
      setErr(e instanceof Error ? e.message : "failed");
    }
  }

  return (
    <div className="space-y-6">
      <section className="rounded-lg border border-border bg-panel p-5">
        <h2 className="font-semibold mb-3">New asset</h2>
        <form onSubmit={create} className="grid md:grid-cols-3 gap-3">
          <input
            placeholder="Name (e.g. main site)"
            value={name}
            onChange={(e) => setName(e.target.value)}
            className="rounded border border-border bg-bg px-3 py-2"
            required
          />
          <input
            placeholder="https://example.com"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            className="rounded border border-border bg-bg px-3 py-2 md:col-span-2"
            required
          />
          <button className="md:col-span-3 rounded bg-accent text-black py-2 font-semibold">
            Add asset
          </button>
        </form>
        {err && <p className="text-critical text-sm mt-3">{err}</p>}
      </section>

      <section className="rounded-lg border border-border bg-panel">
        <table className="w-full text-sm">
          <thead className="text-left text-gray-400 border-b border-border">
            <tr>
              <th className="px-4 py-2">Name</th>
              <th className="px-4 py-2">Target</th>
              <th className="px-4 py-2">Status</th>
              <th className="px-4 py-2"></th>
            </tr>
          </thead>
          <tbody>
            {assets?.length === 0 && (
              <tr>
                <td className="px-4 py-6 text-gray-500" colSpan={4}>
                  No assets yet.
                </td>
              </tr>
            )}
            {assets?.map((a) => (
              <tr key={a.id} className="border-b border-border">
                <td className="px-4 py-2">{a.name}</td>
                <td className="px-4 py-2 text-gray-400">{a.target_url}</td>
                <td className="px-4 py-2">
                  <StatusBadge status={a.verification_status} />
                </td>
                <td className="px-4 py-2 text-right">
                  <Link href={`/assets/${a.id}`} className="text-accent">
                    Manage →
                  </Link>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>
    </div>
  );
}

function StatusBadge({ status }: { status: string }) {
  const color =
    status === "verified" ? "bg-accent/20 text-accent" :
    status === "failed" ? "bg-critical/20 text-critical" :
    "bg-gray-700 text-gray-300";
  return <span className={`px-2 py-0.5 rounded text-xs ${color}`}>{status}</span>;
}
