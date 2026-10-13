// Postgres: one row per submission (ADR 0019). Run directories stay the evidence; the row holds
// the run's state from the daemon's stream and its report for listing.
import { Pool } from 'pg';

export interface RunRow {
  id: string;
  url: string;
  profile: string;
  state: string;
  message: string;
  error: string;
  runId: string | null;
  createdAt: Date;
  startedAt: Date | null;
  finishedAt: Date | null;
  summary: Record<string, unknown> | null;
}

const MIGRATION = `
CREATE TABLE IF NOT EXISTS runs (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  url         text NOT NULL,
  profile     text NOT NULL DEFAULT '',
  state       text NOT NULL DEFAULT 'queued',
  message     text NOT NULL DEFAULT '',
  error       text NOT NULL DEFAULT '',
  run_id      text,
  created_at  timestamptz NOT NULL DEFAULT now(),
  started_at  timestamptz,
  finished_at timestamptz,
  summary     jsonb,
  report      jsonb
);
CREATE INDEX IF NOT EXISTS runs_created ON runs (created_at DESC);
ALTER TABLE runs ADD COLUMN IF NOT EXISTS source text NOT NULL DEFAULT 'dashboard';
CREATE UNIQUE INDEX IF NOT EXISTS runs_run_id ON runs (run_id) WHERE run_id IS NOT NULL;
ALTER TABLE runs ADD COLUMN IF NOT EXISTS report_mtime timestamptz;
`;

const COLS = `id, url, profile, state, message, error, source, run_id AS "runId", created_at AS "createdAt",
  started_at AS "startedAt", finished_at AS "finishedAt", summary`;

export class Db {
  readonly pool: Pool;

  constructor(url: string) {
    this.pool = new Pool({ connectionString: url, max: 5 });
  }

  async migrate(): Promise<void> {
    await this.pool.query(MIGRATION);
  }

  async create(url: string, profile: string): Promise<string> {
    const r = await this.pool.query('INSERT INTO runs (url, profile) VALUES ($1, $2) RETURNING id', [url, profile]);
    return r.rows[0].id;
  }

  async get(id: string): Promise<(RunRow & { report: unknown }) | null> {
    const r = await this.pool.query(`SELECT ${COLS}, report FROM runs WHERE id = $1`, [id]);
    return r.rows[0] ?? null;
  }

  async list(limit: number, before?: Date): Promise<RunRow[]> {
    const r = before
      ? await this.pool.query(`SELECT ${COLS} FROM runs WHERE created_at < $1 ORDER BY created_at DESC LIMIT $2`, [before, limit])
      : await this.pool.query(`SELECT ${COLS} FROM runs ORDER BY created_at DESC LIMIT $1`, [limit]);
    return r.rows;
  }

  async progress(id: string, state: string, message: string, runId: string | null): Promise<void> {
    await this.pool.query(
      `UPDATE runs SET state = $2, message = $3, run_id = COALESCE($4, run_id),
         started_at = COALESCE(started_at, now()) WHERE id = $1`,
      [id, state, message.slice(0, 500), runId],
    );
  }

  async finish(id: string, state: string, error: string, summary: unknown, report: unknown): Promise<void> {
    await this.pool.query(
      'UPDATE runs SET state = $2, error = $3, summary = $4, report = $5, finished_at = now() WHERE id = $1',
      [id, state, error.slice(0, 2000), summary === null ? null : JSON.stringify(summary), report === null ? null : JSON.stringify(report)],
    );
  }

  // Every run with a directory: whether it has finished, and the report.json mtime its stored
  // report was read from (null: not recorded).
  async knownRuns(): Promise<Map<string, { finished: boolean; reportMtime: number | null }>> {
    const r = await this.pool.query(
      `SELECT run_id, state IN ('done', 'failed') AS finished, report_mtime FROM runs WHERE run_id IS NOT NULL`);
    return new Map(r.rows.map((x) => [x.run_id, { finished: x.finished, reportMtime: x.report_mtime?.getTime() ?? null }]));
  }

  // A finished run's report.json was rebuilt (`urljail report`, retention): store the new one.
  async refreshReport(runId: string, summary: unknown, report: unknown, mtime: Date): Promise<void> {
    await this.pool.query(
      `UPDATE runs SET summary = $2, report = $3, report_mtime = $4 WHERE run_id = $1 AND state IN ('done', 'failed')`,
      [runId, summary === null ? null : JSON.stringify(summary), report === null ? null : JSON.stringify(report), mtime],
    );
  }

  // A run started outside the control plane (CLI, feeds), indexed from its directory.
  async importRun(runId: string, url: string, profile: string, state: string, error: string, createdAt: Date,
    finishedAt: Date | null, summary: unknown, report: unknown, reportMtime: Date | null): Promise<void> {
    await this.pool.query(
      `INSERT INTO runs (url, profile, state, error, source, run_id, created_at, started_at, finished_at, summary, report, report_mtime)
       VALUES ($1, $2, $3, $4, 'cli', $5, $6, $6, $7, $8, $9, $10) ON CONFLICT (run_id) WHERE run_id IS NOT NULL DO NOTHING`,
      [url.slice(0, 2048), profile, state, error.slice(0, 2000), runId, createdAt, finishedAt,
        summary === null ? null : JSON.stringify(summary), report === null ? null : JSON.stringify(report), reportMtime],
    );
  }

  // Runs a stopped worker left mid-flight: the daemon tears them down itself; mark them.
  async failStale(): Promise<number> {
    const r = await this.pool.query(
      `UPDATE runs SET state = 'failed', error = 'the control plane stopped during the run', finished_at = now()
       WHERE state NOT IN ('done', 'failed', 'queued')`,
    );
    return r.rowCount ?? 0;
  }
}
