"use client";

import { useEffect, useState } from "react";
import { api, type ApiToken, type ApiTokenCreated } from "@/lib/api";

export default function TokensPage() {
  const [tokens, setTokens] = useState<ApiToken[] | null>(null);
  const [name, setName] = useState("");
  const [created, setCreated] = useState<ApiTokenCreated | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function load() {
    try {
      setTokens(await api<ApiToken[]>("/api/v1/tokens"));
    } catch (e) {
      setErr(e instanceof Error ? e.message : "load failed");
    }
  }

  useEffect(() => {
    void load();
  }, []);

  async function create(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setErr(null);
    try {
      const t = await api<ApiTokenCreated>("/api/v1/tokens", {
        method: "POST",
        body: JSON.stringify({ name }),
      });
      setCreated(t);
      setName("");
      void load();
    } catch (e) {
      setErr(e instanceof Error ? e.message : "create failed");
    } finally {
      setBusy(false);
    }
  }

  async function revoke(id: string) {
    if (!confirm("Revoke this token? It will be unusable immediately.")) return;
    try {
      await api(`/api/v1/tokens/${id}`, { method: "DELETE" });
      void load();
    } catch (e) {
      setErr(e instanceof Error ? e.message : "revoke failed");
    }
  }

  return (
    <div className="space-y-6">
      <header>
        <h1 className="text-2xl font-semibold">API tokens</h1>
        <p className="text-gray-400 text-sm">
          Long-lived bearer tokens for CI/CD. Use them in the
          <code className="mx-1 px-1 bg-bg border border-border rounded">Authorization: Bearer …</code>
          header, just like a session JWT. The plaintext is shown only once at creation.
        </p>
      </header>

      <section className="rounded-lg border border-border bg-panel p-5">
        <h2 className="font-semibold mb-3">New token</h2>
        <form onSubmit={create} className="flex flex-wrap gap-3">
          <input
            placeholder="Name (e.g. github-actions / jenkins)"
            value={name}
            onChange={(e) => setName(e.target.value)}
            className="rounded border border-border bg-bg px-3 py-2 flex-1 min-w-[280px]"
            required
          />
          <button
            disabled={busy}
            className="rounded bg-accent text-black px-4 py-2 font-semibold disabled:opacity-50"
          >
            Create token
          </button>
        </form>
        {err && <p className="text-critical text-sm mt-3">{err}</p>}
      </section>

      {created && (
        <section className="rounded-lg border border-accent/40 bg-accent/5 p-5">
          <h2 className="font-semibold mb-2 text-accent">Token created — copy now, this is the only time it's shown:</h2>
          <pre className="text-xs bg-bg border border-border rounded p-3 break-all">{created.token}</pre>
          <button
            onClick={() => setCreated(null)}
            className="mt-3 rounded border border-border px-3 py-1 text-xs"
          >
            Dismiss
          </button>
        </section>
      )}

      <section className="rounded-lg border border-border bg-panel">
        <table className="w-full text-sm">
          <thead className="text-left text-gray-400 border-b border-border">
            <tr>
              <th className="px-4 py-2">Name</th>
              <th className="px-4 py-2">Prefix</th>
              <th className="px-4 py-2">Last used</th>
              <th className="px-4 py-2">Created</th>
              <th className="px-4 py-2"></th>
            </tr>
          </thead>
          <tbody>
            {tokens?.length === 0 && (
              <tr>
                <td className="px-4 py-6 text-gray-500" colSpan={5}>
                  No tokens yet.
                </td>
              </tr>
            )}
            {tokens?.map((t) => (
              <tr key={t.id} className="border-b border-border">
                <td className="px-4 py-2">{t.name}</td>
                <td className="px-4 py-2 font-mono text-gray-400">{t.token_prefix}…</td>
                <td className="px-4 py-2 text-gray-400">
                  {t.last_used_at ? new Date(t.last_used_at).toLocaleString() : "never"}
                </td>
                <td className="px-4 py-2 text-gray-400">
                  {new Date(t.created_at).toLocaleString()}
                </td>
                <td className="px-4 py-2 text-right">
                  {t.revoked_at ? (
                    <span className="text-xs text-gray-500">revoked</span>
                  ) : (
                    <button onClick={() => revoke(t.id)} className="text-xs text-critical">
                      Revoke
                    </button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>
    </div>
  );
}
