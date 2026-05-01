"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";
import { login } from "@/lib/api";

export default function LoginPage() {
  const router = useRouter();
  const [email, setEmail] = useState("admin@example.com");
  const [password, setPassword] = useState("admin");
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setErr(null);
    setBusy(true);
    try {
      await login(email, password);
      router.push("/assets");
    } catch (e: unknown) {
      setErr(e instanceof Error ? e.message : "login failed");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="max-w-md mx-auto rounded-lg border border-border bg-panel p-6">
      <h1 className="text-xl font-semibold mb-4">Sign in</h1>
      <form onSubmit={submit} className="space-y-3">
        <Field label="Email">
          <input
            type="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            className="w-full rounded border border-border bg-bg px-3 py-2"
            required
          />
        </Field>
        <Field label="Password">
          <input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            className="w-full rounded border border-border bg-bg px-3 py-2"
            required
          />
        </Field>
        {err && <p className="text-critical text-sm">{err}</p>}
        <button
          type="submit"
          disabled={busy}
          className="w-full rounded bg-accent text-black py-2 font-semibold disabled:opacity-50"
        >
          {busy ? "Signing in…" : "Sign in"}
        </button>
      </form>
    </div>
  );
}

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <label className="block">
      <span className="text-sm text-gray-400 mb-1 block">{label}</span>
      {children}
    </label>
  );
}
