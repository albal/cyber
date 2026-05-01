"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import { api, type Scan } from "@/lib/api";

export default function ScansPage() {
  const [scans, setScans] = useState<Scan[] | null>(null);

  useEffect(() => {
    void api<Scan[]>("/api/v1/scans").then(setScans).catch(() => setScans([]));
  }, []);

  return (
    <div className="rounded-lg border border-border bg-panel">
      <table className="w-full text-sm">
        <thead className="text-left text-gray-400 border-b border-border">
          <tr>
            <th className="px-4 py-2">Scan</th>
            <th className="px-4 py-2">Status</th>
            <th className="px-4 py-2">Stage</th>
            <th className="px-4 py-2">Progress</th>
            <th className="px-4 py-2">Created</th>
          </tr>
        </thead>
        <tbody>
          {scans?.length === 0 && (
            <tr>
              <td className="px-4 py-6 text-gray-500" colSpan={5}>No scans yet.</td>
            </tr>
          )}
          {scans?.map((s) => (
            <tr key={s.id} className="border-b border-border">
              <td className="px-4 py-2">
                <Link href={`/scans/${s.id}`} className="text-accent">{s.id.slice(0, 8)}</Link>
              </td>
              <td className="px-4 py-2">{s.status}</td>
              <td className="px-4 py-2 text-gray-400">{s.stage ?? "-"}</td>
              <td className="px-4 py-2">{s.progress}%</td>
              <td className="px-4 py-2 text-gray-400">
                {new Date(s.created_at).toLocaleString()}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
