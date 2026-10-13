// Indexes runs started outside the control plane (the CLI, `urljail feeds`) from their run
// directories, so the dashboard lists every run. Files are untrusted (guest-influenced
// reports): size-capped, parsed as JSON only, and only UUIDv7-named directories are read.
// A finished run whose report.json was rebuilt since it was read gets the new report.
import { readdir, readFile, stat } from 'node:fs/promises';
import { Config } from './config';
import { Db } from './db';
import { insideDir, isRunId, summarize } from './untrusted';

const MAX_REPORT = 64 << 20;

async function readJson(path: string, max: number): Promise<any | null> {
  try {
    const b = await readFile(path);
    return b.length <= max ? JSON.parse(b.toString('utf8')) : null;
  } catch {
    return null;
  }
}

async function mtime(path: string): Promise<Date | null> {
  try {
    return (await stat(path)).mtime;
  } catch {
    return null;
  }
}

// Returns how many runs were added or refreshed.
export async function importRuns(cfg: Config, db: Db): Promise<number> {
  let names: string[];
  try {
    names = await readdir(cfg.runsDir);
  } catch {
    return 0;
  }
  const known = await db.knownRuns();
  let n = 0;
  for (const name of names) {
    if (!isRunId(name)) continue;
    const reportPath = insideDir(cfg.runsDir, name, 'report.json');
    const k = known.get(name);
    if (k) {
      if (!k.finished) continue; // the worker owns it
      const m = await mtime(reportPath);
      if (m && (k.reportMtime === null || m.getTime() > k.reportMtime)) {
        const report = await readJson(reportPath, MAX_REPORT);
        if (report) {
          await db.refreshReport(name, summarize(report), report, m);
          n++;
        }
      }
      continue;
    }
    const meta = await readJson(insideDir(cfg.runsDir, name, 'meta.json'), 1 << 20);
    if (!meta || typeof meta.url !== 'string' || meta.url.startsWith('selftest:')) continue;
    if (!meta.status) continue; // still running, or interrupted and not yet recovered by the daemon
    const reportMtime = await mtime(reportPath);
    const report = await readJson(reportPath, MAX_REPORT);
    const started = Date.parse(meta.started_at);
    const ended = Date.parse(meta.ended_at);
    await db.importRun(
      name, meta.url, typeof meta.profile === 'string' ? meta.profile : '',
      meta.status === 'completed' ? 'done' : 'failed', meta.status === 'completed' ? '' : String(meta.error ?? meta.status),
      Number.isNaN(started) ? new Date() : new Date(started), Number.isNaN(ended) ? null : new Date(ended),
      report ? summarize(report) : null, report, report ? reportMtime : null,
    );
    n++;
  }
  return n;
}
