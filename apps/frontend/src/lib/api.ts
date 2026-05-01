"use client";

const BASE = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";

export function token(): string | null {
  if (typeof window === "undefined") return null;
  return window.localStorage.getItem("cyberscan_token");
}

function authHeaders(): HeadersInit {
  const t = token();
  return t ? { Authorization: `Bearer ${t}` } : {};
}

export async function api<T = unknown>(
  path: string,
  init: RequestInit = {},
): Promise<T> {
  const r = await fetch(`${BASE}${path}`, {
    ...init,
    headers: {
      "Content-Type": "application/json",
      ...authHeaders(),
      ...(init.headers ?? {}),
    },
  });
  if (!r.ok) {
    const text = await r.text().catch(() => "");
    throw new Error(`${r.status} ${r.statusText}: ${text}`);
  }
  if (r.status === 204) return undefined as T;
  return (await r.json()) as T;
}

export async function login(email: string, password: string): Promise<string> {
  const body = new URLSearchParams();
  body.set("username", email);
  body.set("password", password);
  const r = await fetch(`${BASE}/api/v1/auth/login`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body,
  });
  if (!r.ok) throw new Error("invalid credentials");
  const data = (await r.json()) as { access_token: string };
  window.localStorage.setItem("cyberscan_token", data.access_token);
  return data.access_token;
}

export interface Asset {
  id: string;
  name: string;
  target_url: string;
  hostname: string;
  verification_method: string;
  verification_token: string;
  verification_status: string;
  verified_at: string | null;
  created_at: string;
}

export interface Scan {
  id: string;
  asset_id: string;
  status: string;
  stage: string | null;
  progress: number;
  started_at: string | null;
  finished_at: string | null;
  error: string | null;
  summary: Record<string, unknown> | null;
  created_at: string;
}

export interface Finding {
  id: string;
  scan_id: string;
  title: string;
  template_id: string | null;
  cve_ids: string[];
  cwe_ids: string[];
  severity: string;
  cvss_score: number | null;
  epss_score: number | null;
  is_kev: boolean;
  risk_score: number;
  location: string | null;
  matcher_name: string | null;
  request: string | null;
  response_excerpt: string | null;
  remediation: string | null;
  references: string[];
  compliance_tags: string[];
  diff_status: string | null;
}

export const API_BASE = BASE;
