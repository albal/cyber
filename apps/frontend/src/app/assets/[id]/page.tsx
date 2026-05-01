"use client";

import { useParams, useRouter } from "next/navigation";
import { useEffect, useState } from "react";
import { api, type Asset, type Scan } from "@/lib/api";

interface VerificationInstructions {
  method: string;
  token: string;
  instructions: string;
}

export default function AssetDetailPage() {
  const params = useParams<{ id: string }>();
  const router = useRouter();
  const id = params.id;

  const [asset, setAsset] = useState<Asset | null>(null);
  const [instr, setInstr] = useState<VerificationInstructions | null>(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  async function load() {
    setAsset(await api<Asset>(`/api/v1/assets/${id}`));
    setInstr(await api<VerificationInstructions>(`/api/v1/assets/${id}/verify`));
  }

  useEffect(() => {
    void load();
  }, [id]);

  async function verify() {
    setBusy(true);
    setErr(null);
    try {
      const updated = await api<Asset>(`/api/v1/assets/${id}/verify`, { method: "POST" });
      setAsset(updated);
    } catch (e) {
      setErr(e instanceof Error ? e.message : "verification failed");
    } finally {
      setBusy(false);
    }
  }

  async function startScan() {
    setBusy(true);
    setErr(null);
    try {
      const scan = await api<Scan>("/api/v1/scans", {
        method: "POST",
        body: JSON.stringify({ asset_id: id }),
      });
      router.push(`/scans/${scan.id}`);
    } catch (e) {
      setErr(e instanceof Error ? e.message : "scan failed");
    } finally {
      setBusy(false);
    }
  }

  if (!asset) return <p className="text-gray-500">Loading…</p>;

  return (
    <div className="space-y-6">
      <header>
        <h1 className="text-2xl font-semibold">{asset.name}</h1>
        <p className="text-gray-400">{asset.target_url}</p>
      </header>

      <section className="rounded-lg border border-border bg-panel p-5">
        <h2 className="font-semibold mb-2">Ownership verification</h2>
        <p className="text-sm text-gray-400 mb-3">Status: <b>{asset.verification_status}</b></p>
        {instr && (
          <pre className="whitespace-pre-wrap text-xs bg-bg border border-border rounded p-3">
{instr.instructions}
          </pre>
        )}
        <div className="mt-3 flex gap-3">
          <button
            onClick={verify}
            disabled={busy}
            className="rounded border border-border px-4 py-2 text-sm disabled:opacity-50"
          >
            {busy ? "Verifying…" : "Verify"}
          </button>
          <button
            onClick={startScan}
            disabled={busy || asset.verification_status !== "verified"}
            className="rounded bg-accent text-black px-4 py-2 text-sm font-semibold disabled:opacity-50"
          >
            Start scan
          </button>
        </div>
        {err && <p className="text-critical text-sm mt-3">{err}</p>}
      </section>
    </div>
  );
}
