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
  label?: Label | null;
}

export interface Label { verdict: string; kind: string; brand: string; note: string; labelledAt?: string }

export interface Evaluation {
  phish: number;
  other: number;
  unsure: number;
  thresholds: Array<{ name: string; flaggedPhish: number; flaggedOther: number }>;
  indicators: Array<{ id: string; flaggedPhish: number; flaggedOther: number }>;
  byKind: Array<{ kind: string; phish: number; flagged: number }>;
  missed: Array<{ id: string; url: string; kind: string; brand: string; note: string }>;
  falsePositives: Array<{ id: string; url: string; verdict: string; note: string; indicators: string[] }>;
}

export interface ListFilter { view?: string; indicator?: string; brand?: string }

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
  list: (f: ListFilter = {}) => {
    const q = new URLSearchParams({ limit: '100' });
    for (const [k, v] of Object.entries(f)) if (v) q.set(k, v);
    return json<{ runs: RunRow[] }>(`/api/runs?${q}`);
  },
  label: (id: string, l: Label) =>
    json<{ ok: boolean }>(`/api/runs/${encodeURIComponent(id)}/label`, { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(l) }),
  unlabel: (id: string) => json<{ ok: boolean }>(`/api/runs/${encodeURIComponent(id)}/label`, { method: 'DELETE' }),
  evaluation: () => json<Evaluation>('/api/evaluation'),
  labelsTsv: () => call('/api/labels.tsv'),
  get: (id: string) => json<RunRow & { report: any }>(`/api/runs/${encodeURIComponent(id)}`),
  submit: (url: string, profile: string) =>
    json<{ id: string }>('/api/runs', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ url, profile }) }),
  similar: (id: string) => json<{ maxDistance: number; runs: (RunRow & { distance: number })[] }>(`/api/runs/${encodeURIComponent(id)}/similar`),
  har: (id: string) => call(`/api/runs/${encodeURIComponent(id)}/har`),
  screenshot: (id: string) => call(`/api/runs/${encodeURIComponent(id)}/screenshot`),
};

export const active = (s: string) => s !== 'done' && s !== 'failed';
