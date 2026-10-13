// BullMQ queue and worker: one job per submission, never retried (a detonation is an action
// on a live site; it is repeated only on purpose). Concurrency follows the daemon's VM slots.
import { Queue, Worker } from 'bullmq';
import { readFile } from 'node:fs/promises';
import { basename } from 'node:path';
import { Config } from './config';
import { DaemonClient } from './daemon';
import { Db } from './db';
import { insideDir, isRunId, summarize } from './untrusted';

export const QUEUE = 'detonations';
const MAX_REPORT = 64 << 20;

function redisConnection(url: string) {
  const u = new URL(url);
  return { host: u.hostname, port: Number(u.port || 6379), password: decodeURIComponent(u.password) || undefined, maxRetriesPerRequest: null };
}

export function makeQueue(cfg: Config): Queue {
  return new Queue(QUEUE, {
    connection: redisConnection(cfg.redisUrl),
    defaultJobOptions: { attempts: 1, removeOnComplete: 1000, removeOnFail: 1000 },
  });
}

const shortState = (s: string) => s.replace(/^RUN_STATE_/, '').toLowerCase();

export function startWorker(cfg: Config, db: Db, daemon: DaemonClient, concurrency: number): Worker {
  return new Worker(
    QUEUE,
    async (job) => {
      const id: string = job.data.id;
      const row = await db.get(id);
      if (!row) return;
      let runId: string | null = null;
      const final = await daemon
        .detonate(row.url, row.profile, (p) => {
          const rid = basename(p.runDir || '');
          if (isRunId(rid)) runId = rid;
          void db.progress(id, shortState(p.state), p.message || p.error, runId);
        })
        .catch((err: Error) => ({ state: 'RUN_STATE_FAILED', message: '', runDir: '', error: err.message }));
      let report: unknown = null;
      if (runId) {
        try {
          const path = insideDir(cfg.runsDir, runId, 'report.json');
          const buf = await readFile(path);
          if (buf.length <= MAX_REPORT) report = JSON.parse(buf.toString('utf8'));
        } catch {
          // a run that failed early has no report; the row keeps the daemon's error
        }
      }
      const ok = final.state === 'RUN_STATE_DONE';
      await db.finish(id, ok ? 'done' : 'failed', ok ? '' : final.error || 'failed', report ? summarize(report) : null, report);
    },
    { connection: redisConnection(cfg.redisUrl), concurrency, autorun: true },
  );
}
