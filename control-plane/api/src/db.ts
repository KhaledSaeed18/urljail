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
CREATE TABLE IF NOT EXISTS labels (
  run         uuid PRIMARY KEY REFERENCES runs(id) ON DELETE CASCADE,
  verdict     text NOT NULL,
  kind        text NOT NULL DEFAULT '',
  brand       text NOT NULL DEFAULT '',
  note        text NOT NULL DEFAULT '',
  labelled_at timestamptz NOT NULL DEFAULT now()
);
`;

// A run's label as a JSON object (null when unlabelled), for the row queries.
const LABEL = `(SELECT row_to_json(l) FROM (SELECT verdict, kind, brand, note, labelled_at AS "labelledAt"
  FROM labels WHERE labels.run = runs.id) l) AS label`;

export interface ListFilter {
  view?: 'all' | 'unlabelled' | 'labelled';
  indicator?: string;
  brand?: string;
}

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
    const r = await this.pool.query(`SELECT ${COLS}, ${LABEL}, report FROM runs WHERE id = $1`, [id]);
    return r.rows[0] ?? null;
  }

  // Newest first. "unlabelled" is the review queue: finished runs whose page loaded (no
  // navigation error) and that nobody has labelled yet.
  async list(limit: number, before?: Date, f: ListFilter = {}): Promise<RunRow[]> {
    const where: string[] = [];
    const args: unknown[] = [];
    const arg = (v: unknown) => `$${args.push(v)}`;
    if (before) where.push(`created_at < ${arg(before)}`);
    if (f.view === 'unlabelled') {
      where.push(`state = 'done' AND COALESCE(summary->>'navError', '') = '' AND NOT EXISTS (SELECT 1 FROM labels WHERE labels.run = runs.id)`);
    } else if (f.view === 'labelled') {
      where.push('EXISTS (SELECT 1 FROM labels WHERE labels.run = runs.id)');
    }
    if (f.indicator) where.push(`summary->'indicators' @> ${arg(JSON.stringify([{ id: f.indicator }]))}::jsonb`);
    if (f.brand) where.push(`summary->'indicators' @> ${arg(JSON.stringify([{ brand: f.brand }]))}::jsonb`);
    const sql = `SELECT ${COLS}, ${LABEL} FROM runs ${where.length ? 'WHERE ' + where.join(' AND ') : ''}
      ORDER BY created_at DESC LIMIT ${arg(limit)}`;
    return (await this.pool.query(sql, args)).rows;
  }

  async setLabel(id: string, l: { verdict: string; kind: string; brand: string; note: string }): Promise<boolean> {
    const r = await this.pool.query(
      `INSERT INTO labels (run, verdict, kind, brand, note) SELECT id, $2, $3, $4, $5 FROM runs WHERE id = $1
       ON CONFLICT (run) DO UPDATE SET verdict = $2, kind = $3, brand = $4, note = $5, labelled_at = now()`,
      [id, l.verdict, l.kind, l.brand, l.note]);
    return (r.rowCount ?? 0) > 0;
  }

  async deleteLabel(id: string): Promise<void> {
    await this.pool.query('DELETE FROM labels WHERE run = $1', [id]);
  }

  // Every labelled run with its indicators, for scoring and export.
  async labelled(): Promise<Array<{ id: string; runId: string | null; url: string; createdAt: Date; verdict: string; kind: string;
    brand: string; note: string; indicators: Array<{ id: string; severity: string; brand: string }> }>> {
    const r = await this.pool.query(
      `SELECT runs.id, runs.run_id AS "runId", runs.url, runs.created_at AS "createdAt", l.verdict, l.kind, l.brand, l.note,
              COALESCE(runs.summary->'indicators', '[]'::jsonb) AS indicators
         FROM runs JOIN labels l ON l.run = runs.id ORDER BY runs.created_at`);
    return r.rows;
  }

  async idForRunId(runId: string): Promise<string | null> {
    const r = await this.pool.query('SELECT id FROM runs WHERE run_id = $1', [runId]);
    return r.rows[0]?.id ?? null;
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

  // Runs whose screenshot hash is within maxDist bits of this one's (internal/visual), closest
  // first. The hash was checked against PHASH when the summary was written.
  async similar(id: string, maxDist: number, limit: number): Promise<Array<RunRow & { distance: number }>> {
    const r = await this.pool.query(
      `WITH me AS (SELECT ('x' || (summary->>'phash'))::bit(64) AS h FROM runs WHERE id = $1 AND summary->>'phash' ~ '^[0-9a-f]{16}$')
       SELECT ${COLS}, bit_count(('x' || (r.summary->>'phash'))::bit(64) # me.h)::int AS distance
         FROM runs r, me
        WHERE r.id <> $1 AND r.summary->>'phash' ~ '^[0-9a-f]{16}$'
          AND bit_count(('x' || (r.summary->>'phash'))::bit(64) # me.h) <= $2
        ORDER BY distance, r.created_at DESC LIMIT $3`,
      [id, maxDist, limit],
    );
    return r.rows;
  }

  // Recomputes summaries written by an older summarize() from the stored reports, in batches.
  async resummarize(version: number, summarize: (report: unknown) => unknown): Promise<number> {
    let n = 0;
    for (;;) {
      const r = await this.pool.query(
        `SELECT id, report FROM runs WHERE report IS NOT NULL AND COALESCE((summary->>'v')::int, 1) < $1 LIMIT 100`, [version]);
      if (r.rows.length === 0) return n;
      for (const row of r.rows) {
        await this.pool.query('UPDATE runs SET summary = $2 WHERE id = $1', [row.id, JSON.stringify(summarize(row.report))]);
        n++;
      }
    }
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
