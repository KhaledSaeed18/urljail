// Pure helpers for data that comes from detonated pages (titles, URLs, files in run
// directories): everything here treats its input as hostile. Unit-tested in untrusted.test.ts.
import { isAbsolute, relative, resolve } from 'node:path';

export const MAX_URL = 2048;

// validateSubmission checks a URL before it's queued. The daemon applies its own policy
// (http/https, ports, live mode for non-allowlisted hosts); this only rejects junk early.
export function validateSubmission(body: unknown): { url: string; profile: string } {
  if (typeof body !== 'object' || body === null) throw new Error('body must be a JSON object');
  const { url, profile } = body as Record<string, unknown>;
  if (typeof url !== 'string' || url.length === 0 || url.length > MAX_URL) throw new Error(`url must be a string of 1..${MAX_URL} characters`);
  if (/[\u0000- \u007f]/.test(url)) throw new Error('url contains spaces or control characters');
  let u: URL;
  try {
    u = new URL(url);
  } catch {
    throw new Error('url is not an absolute URL');
  }
  if (u.protocol !== 'http:' && u.protocol !== 'https:') throw new Error('only http and https URLs');
  if (profile !== undefined && (typeof profile !== 'string' || !/^[a-z0-9~+-]{0,40}$/.test(profile))) throw new Error('bad profile name');
  return { url, profile: (profile as string | undefined) ?? '' };
}

// insideDir resolves name under dir and refuses anything that escapes it.
export function insideDir(dir: string, ...parts: string[]): string {
  const p = resolve(dir, ...parts);
  const rel = relative(dir, p);
  if (rel === '' || rel.startsWith('..') || isAbsolute(rel)) throw new Error('path outside the runs directory');
  return p;
}

// A run directory is named by its UUIDv7 run ID.
export function isRunId(s: unknown): s is string {
  return typeof s === 'string' && /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(s);
}

const PNG = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
export const isPng = (b: Buffer): boolean => b.length > PNG.length && b.subarray(0, PNG.length).equals(PNG);

// A screenshot hash as the report writes it (internal/visual): 16 lowercase hex digits.
export const PHASH = /^[0-9a-f]{16}$/;

const clip = (v: unknown, n: number): string => (typeof v === 'string' ? v.slice(0, n) : '');

// SUMMARY_VERSION goes up whenever summarize adds or changes a field; stored summaries of an
// older version are recomputed from the stored report at start (Db.resummarize).
export const SUMMARY_VERSION = 2;

// summarize extracts the fields the run list shows from a report (urljail.report.v0, protojson).
export function summarize(report: any): Record<string, unknown> {
  const nav = report?.navigation ?? {};
  const net = report?.network ?? {};
  const rec = report?.reconciliation ?? {};
  const len = (a: unknown) => (Array.isArray(a) ? a.length : 0);
  return {
    v: SUMMARY_VERSION,
    status: clip(report?.run?.status, 40),
    finalUrl: clip(nav.finalUrl ?? nav.final_url, MAX_URL),
    title: clip(nav.title, 300),
    navError: clip(nav.error, 200),
    redirects: len(nav.redirectChain ?? nav.redirect_chain),
    requests: len(net.requests),
    domains: (Array.isArray(net.domains) ? net.domains : []).slice(0, 50).map((d: any) => clip(d?.registrable, 253)),
    flows: len(net.flows),
    blocked: len(net.blocked),
    consistent: rec.consistent === true,
    gaps: len(report?.gaps),
    phash: typeof report?.page?.screenshot_phash === 'string' && PHASH.test(report.page.screenshot_phash) ? report.page.screenshot_phash : '',
    passwordFields: Number.isInteger(report?.page?.password_fields) ? Math.min(report.page.password_fields, 1000) : 0,
    indicators: (Array.isArray(report?.indicators) ? report.indicators : []).slice(0, 10).map((i: any) => ({
      id: clip(i?.id, 60), severity: clip(i?.severity, 10), brand: clip(i?.brand, 40),
    })),
  };
}
