// Server-side client for the urljail API (ADR 0019). Only the dashboard's server holds the
// token; the browser never sees it. Never import this from a client component.
import 'server-only';

const base = () => process.env.URLJAIL_API_URL ?? 'http://127.0.0.1:7801';

async function call(path: string, init: RequestInit = {}): Promise<Response> {
  const token = process.env.URLJAIL_API_TOKEN;
  if (!token) throw new Error('URLJAIL_API_TOKEN is not set (control-plane/scripts/setup.sh)');
  return fetch(base() + path, {
    ...init,
    cache: 'no-store',
    headers: { ...(init.headers ?? {}), Authorization: `Bearer ${token}`, Host: '127.0.0.1' },
  });
}

async function json<T>(path: string, init?: RequestInit): Promise<T> {
  const r = await call(path, init);
  const body = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error((body as { message?: string }).message ?? `API ${r.status}`);
  return body as T;
}

export interface RunRow {
  id: string;
  url: string;
  profile: string;
  source: string; // 'dashboard' or 'cli' (CLI, feeds)
  state: string;
  message: string;
  error: string;
  runId: string | null;
  createdAt: string;
  startedAt: string | null;
  finishedAt: string | null;
  summary: Summary | null;
}

export interface Summary {
  status: string;
  finalUrl: string;
  title: string;
  navError: string;
  redirects: number;
  requests: number;
  domains: string[];
  flows: number;
  blocked: number;
  consistent: boolean;
  gaps: number;
  phash?: string;
  passwordFields?: number;
  indicators?: { id: string; severity: string; brand: string }[];
}

export interface Status {
  daemon: { urljail: string; egressMode: string; profiles: string[]; maxVms: number } | null;
  daemonError?: string;
  queue: Record<string, number>;
}

export const api = {
  status: () => json<Status>('/api/status'),
  list: () => json<{ runs: RunRow[] }>('/api/runs?limit=100'),
  get: (id: string) => json<RunRow & { report: any }>(`/api/runs/${encodeURIComponent(id)}`),
  submit: (url: string, profile: string) =>
    json<{ id: string }>('/api/runs', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ url, profile }) }),
  similar: (id: string) => json<{ maxDistance: number; runs: (RunRow & { distance: number })[] }>(`/api/runs/${encodeURIComponent(id)}/similar`),
  har: (id: string) => call(`/api/runs/${encodeURIComponent(id)}/har`),
  screenshot: (id: string) => call(`/api/runs/${encodeURIComponent(id)}/screenshot`),
};

export const active = (s: string) => s !== 'done' && s !== 'failed';
