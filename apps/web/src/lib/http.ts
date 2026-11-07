import { useSyncExternalStore } from 'react';

/** Every request made by a demo is recorded so the UI can show raw HTTP. */
export interface HttpEntry {
  id: number;
  at: string;
  method: string;
  url: string;
  reqHeaders: Record<string, string>;
  reqBody?: string;
  status: number;
  resHeaders: Record<string, string>;
  resBody: unknown;
  ms: number;
}

let entries: HttpEntry[] = [];
let seq = 0;
const listeners = new Set<() => void>();
const emit = () => listeners.forEach((l) => l());

export const httpLog = {
  subscribe: (l: () => void) => { listeners.add(l); return () => listeners.delete(l); },
  get: () => entries,
  clear: () => { entries = []; emit(); },
};
export const useHttpLog = () => useSyncExternalStore(httpLog.subscribe, httpLog.get);

const SHOW_RES_HEADERS = ['www-authenticate', 'set-cookie', 'ratelimit', 'ratelimit-policy', 'content-type', 'cache-control'];

export interface CallOpts {
  method?: string;
  headers?: Record<string, string>;
  json?: unknown;
  form?: Record<string, string>;
  credentials?: RequestCredentials;
}

export async function call<T = any>(url: string, opts: CallOpts = {}): Promise<{ status: number; body: T; headers: Headers }> {
  // Custom header only for our own API (same-origin) – cross-origin it would force a CORS preflight
  const headers: Record<string, string> = { ...(url.startsWith('/') ? { 'X-Requested-With': 'fetch' } : {}), ...opts.headers };
  let body: string | undefined;
  if (opts.json !== undefined) { headers['Content-Type'] = 'application/json'; body = JSON.stringify(opts.json); }
  if (opts.form) { headers['Content-Type'] = 'application/x-www-form-urlencoded'; body = new URLSearchParams(opts.form).toString(); }
  const method = opts.method ?? (body ? 'POST' : 'GET');
  const t0 = performance.now();
  const res = await fetch(url, { method, headers, body, credentials: opts.credentials ?? 'same-origin' });
  const text = await res.text();
  let parsed: unknown = text;
  try { parsed = JSON.parse(text); } catch { /* text */ }
  const resHeaders: Record<string, string> = {};
  res.headers.forEach((v, k) => { if (SHOW_RES_HEADERS.includes(k)) resHeaders[k] = v; });
  entries = [{ id: ++seq, at: new Date().toLocaleTimeString(), method, url, reqHeaders: headers, reqBody: body, status: res.status, resHeaders, resBody: parsed, ms: Math.round(performance.now() - t0) }, ...entries].slice(0, 30);
  emit();
  return { status: res.status, body: parsed as T, headers: res.headers };
}

/** Set VITE_AUTH_SERVER at build time when the auth server isn't on localhost (e.g. on Vercel). */
export const AUTH_SERVER: string = import.meta.env.VITE_AUTH_SERVER ?? 'http://localhost:4000';
