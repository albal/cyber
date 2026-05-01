"use client";

import { useParams } from "next/navigation";
import { useEffect, useState } from "react";
import { api, API_BASE, token, type Finding, type Scan } from "@/lib/api";

const SEV_COLOR: Record<string, string> = {
  critical: "bg-critical/20 text-critical",
  high: "bg-high/20 text-high",
  medium: "bg-medium/20 text-medium",
  low: "bg-low/20 text-low",
  info: "bg-gray-700 text-gray-300",
};

export default function ScanDetailPage() {
  const { id } = useParams<{ id: string }>();
  const [scan, setScan] = useState<Scan | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);

  useEffect(() => {
    let cancelled = false;
    let timer: ReturnType<typeof setInterval> | null = null;

    async function loadFindings() {
      try {
        const f = await api<Finding[]>(`/api/v1/scans/${id}/findings`);
        if (!cancelled) setFindings(f);
      } catch {
        // findings table may be empty until completion
      }
    }

    async function poll() {
      try {
        const s = await api<Scan>(`/api/v1/scans/${id}`);
        if (cancelled) return;
        setScan(s);
        if (["completed", "failed", "partial"].includes(s.status)) {
          if (timer) clearInterval(timer);
          await loadFindings();
        }
      } catch {
        // transient
      }
    }

    void poll();
    timer = setInterval(poll, 2000);
    return () => {
      cancelled = true;
      if (timer) clearInterval(timer);
    };
  }, [id]);

  if (!scan) return <p className="text-gray-500">Loading…</p>;

  const summary = (scan.summary ?? {}) as Record<string, unknown>;

  return (
    <div className="space-y-6">
      <header>
        <h1 className="text-2xl font-semibold">Scan {scan.id.slice(0, 8)}</h1>
        <p className="text-gray-400">
          Status: <b>{scan.status}</b> · Stage: {scan.stage ?? "-"} · Progress: {scan.progress}%
        </p>
        <div className="h-2 bg-bg rounded mt-2 overflow-hidden border border-border">
          <div className="h-full bg-accent" style={{ width: `${scan.progress}%` }} />
        </div>
      </header>

      {scan.error && (
        <p className="rounded border border-critical/40 bg-critical/10 text-critical p-3 text-sm">
          {scan.error}
        </p>
      )}

      {scan.status === "completed" && (
        <section className="rounded-lg border border-border bg-panel p-5">
          <h2 className="font-semibold mb-2">Summary</h2>
          <pre className="text-xs text-gray-400">{JSON.stringify(summary, null, 2)}</pre>
        </section>
      )}

      <section className="rounded-lg border border-border bg-panel">
        <table className="w-full text-sm">
          <thead className="text-left text-gray-400 border-b border-border">
            <tr>
              <th className="px-4 py-2">Severity</th>
              <th className="px-4 py-2">Risk</th>
              <th className="px-4 py-2">Title</th>
              <th className="px-4 py-2">CVE</th>
              <th className="px-4 py-2">Diff</th>
              <th className="px-4 py-2">Location</th>
            </tr>
          </thead>
          <tbody>
            {findings.length === 0 && scan.status === "completed" && (
              <tr>
                <td className="px-4 py-6 text-gray-500" colSpan={6}>
                  No findings.
                </td>
              </tr>
            )}
            {findings.map((f) => (
              <tr key={f.id} className="border-b border-border align-top">
                <td className="px-4 py-2">
                  <span className={`px-2 py-0.5 rounded text-xs ${SEV_COLOR[f.severity] ?? ""}`}>
                    {f.severity}
                  </span>
                  {f.is_kev && (
                    <span className="ml-2 px-2 py-0.5 rounded text-xs bg-critical/20 text-critical">
                      KEV
                    </span>
                  )}
                </td>
                <td className="px-4 py-2 font-mono">{f.risk_score.toFixed(1)}</td>
                <td className="px-4 py-2 max-w-md">
                  <div>{f.title}</div>
                  {f.compliance_tags.length > 0 && (
                    <div className="mt-1 flex flex-wrap gap-1">
                      {f.compliance_tags.map((t) => (
                        <span
                          key={t}
                          className="text-xs px-1.5 py-0.5 rounded bg-bg border border-border text-gray-400"
                        >
                          {t}
                        </span>
                      ))}
                    </div>
                  )}
                </td>
                <td className="px-4 py-2 text-gray-400">
                  {f.cve_ids.join(", ") || "-"}
                </td>
                <td className="px-4 py-2 text-gray-400">{f.diff_status ?? "-"}</td>
                <td className="px-4 py-2 text-gray-500 break-all">{f.location ?? "-"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>
    </div>
  );
}
