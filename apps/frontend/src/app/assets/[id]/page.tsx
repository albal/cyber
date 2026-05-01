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
  const [intrusive, setIntrusive] = useState(false);
  const [cron, setCron] = useState("");
  const [scheduleEnabled, setScheduleEnabled] = useState(false);

  async function load() {
    const a = await api<Asset>(`/api/v1/assets/${id}`);
    setAsset(a);
    setCron(a.schedule_cron ?? "");
    setScheduleEnabled(a.schedule_enabled);
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
        body: JSON.stringify({ asset_id: id, intrusive }),
      });
      router.push(`/scans/${scan.id}`);
    } catch (e) {
      setErr(e instanceof Error ? e.message : "scan failed");
    } finally {
      setBusy(false);
    }
  }

  async function saveSchedule() {
    setBusy(true);
    setErr(null);
    try {
      const updated = await api<Asset>(`/api/v1/assets/${id}/schedule`, {
        method: "PUT",
        body: JSON.stringify({
          schedule_cron: cron || null,
          schedule_enabled: scheduleEnabled,
        }),
      });
      setAsset(updated);
    } catch (e) {
      setErr(e instanceof Error ? e.message : "schedule update failed");
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
        <p className="text-sm text-gray-400 mb-3">
          Status: <b>{asset.verification_status}</b>
          {asset.verified_at && (
            <span className="text-gray-500"> · verified {new Date(asset.verified_at).toLocaleString()}</span>
          )}
        </p>
        {instr && (
          <pre className="whitespace-pre-wrap text-xs bg-bg border border-border rounded p-3">{instr.instructions}</pre>
        )}
        <div className="mt-3 flex flex-wrap gap-3 items-center">
          <button
            onClick={verify}
            disabled={busy}
            className="rounded border border-border px-4 py-2 text-sm disabled:opacity-50"
          >
            {busy ? "Verifying…" : "Verify"}
          </button>
          <label className="flex items-center gap-2 text-sm text-gray-300">
            <input
              type="checkbox"
              checked={intrusive}
              onChange={(e) => setIntrusive(e.target.checked)}
            />
            Intrusive (active) scan — requires re-verify within 7 days
          </label>
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

      <section className="rounded-lg border border-border bg-panel p-5">
        <h2 className="font-semibold mb-2">Scheduled scans</h2>
        <p className="text-sm text-gray-400 mb-3">
          Cron expression (UTC). Leave empty to disable.
          {asset.last_scheduled_at && (
            <span className="text-gray-500"> · last fired {new Date(asset.last_scheduled_at).toLocaleString()}</span>
          )}
        </p>
        <div className="flex flex-wrap items-center gap-3">
          <input
            placeholder="0 6 * * 1   (Mondays 06:00 UTC)"
            value={cron}
            onChange={(e) => setCron(e.target.value)}
            className="rounded border border-border bg-bg px-3 py-2 font-mono text-sm w-80"
          />
          <label className="flex items-center gap-2 text-sm text-gray-300">
            <input
              type="checkbox"
              checked={scheduleEnabled}
              onChange={(e) => setScheduleEnabled(e.target.checked)}
            />
            Enabled
          </label>
          <button
            onClick={saveSchedule}
            disabled={busy}
            className="rounded border border-border px-4 py-2 text-sm disabled:opacity-50"
          >
            Save schedule
          </button>
        </div>
      </section>
    </div>
  );
}
