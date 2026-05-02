"use client";

// Default to relative URLs so requests go to the Next.js server, which
// proxies /api/* to the backend (see next.config.ts rewrites). This avoids
// CORS entirely and removes a class of "Failed to fetch" issues caused by
// browsers, extensions, or hosts/networks that mishandle cross-origin
// localhost requests. Set NEXT_PUBLIC_API_URL to opt out (e.g., when the
// frontend is built without a co-located proxy).
const BASE = process.env.NEXT_PUBLIC_API_URL ?? "";

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
  const url = `${BASE}${path}`;
  const method = (init.method ?? "GET").toUpperCase();
  let r: Response;
  try {
    // Only set Content-Type when there's a body. Adding it on GET requests
    // unnecessarily promotes them to "non-simple" CORS, which forces a
    // preflight and is a common cause of mysterious "Failed to fetch" errors
    // when the preflight is rejected.
    const headers: Record<string, string> = { ...authHeaders() } as Record<string, string>;
    if (init.body != null) headers["Content-Type"] = "application/json";
    Object.assign(headers, init.headers ?? {});

    r = await fetch(url, { ...init, headers });
  } catch (e) {
    const msg = e instanceof Error ? e.message : "fetch failed";
    // Helpful for the user opening DevTools — they'll see the underlying error.
    // eslint-disable-next-line no-console
    console.error(`[api] ${method} ${url} — network error:`, e);
    throw new Error(
      `network error contacting ${BASE} (${method} ${path}): ${msg}. ` +
        `Check that the backend is up (curl ${BASE}/healthz) and CORS is configured.`,
    );
  }
  if (!r.ok) {
    const text = await r.text().catch(() => "");
    // eslint-disable-next-line no-console
    console.error(`[api] ${method} ${url} -> ${r.status} ${r.statusText}`, text);
    throw new Error(`${r.status} ${r.statusText}${text ? `: ${text}` : ""}`);
  }
  if (r.status === 204) return undefined as T;
  return (await r.json()) as T;
}

export async function login(email: string, password: string): Promise<string> {
  const body = new URLSearchParams();
  body.set("username", email);
  body.set("password", password);
  let r: Response;
  try {
    r = await fetch(`${BASE}/api/v1/auth/login`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body,
    });
  } catch (e) {
    throw new Error(
      `network error contacting ${BASE} — is the backend reachable from your browser? (${
        e instanceof Error ? e.message : "fetch failed"
      })`,
    );
  }
  if (!r.ok) {
    const text = await r.text().catch(() => "");
    throw new Error(`${r.status} ${r.statusText}${text ? `: ${text}` : ""}`);
  }
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
  schedule_cron: string | null;
  schedule_enabled: boolean;
  last_scheduled_at: string | null;
  enumerate_subdomains: boolean;
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
  intrusive: boolean;
  created_at: string;
}

export interface ApiToken {
  id: string;
  name: string;
  token_prefix: string;
  revoked_at: string | null;
  last_used_at: string | null;
  created_at: string;
}

export interface ApiTokenCreated extends ApiToken {
  token: string; // plaintext, returned once
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
