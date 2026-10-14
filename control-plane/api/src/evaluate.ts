// Scoring the indicators against people's labels (journal P7): at each severity threshold, and
// per indicator, how many labelled phishing runs it flags and how many runs that aren't.
export interface LabelledRun {
  id: string;
  url: string;
  verdict: string;
  kind: string;
  brand: string;
  note: string;
  indicators: Array<{ id: string; severity: string; brand: string }>;
}

export interface Score { flaggedPhish: number; flaggedOther: number }

export interface Evaluation {
  phish: number;
  other: number; // benign, unsure excluded, real-site included
  unsure: number;
  thresholds: Array<{ name: string } & Score>;
  indicators: Array<{ id: string } & Score>;
  byKind: Array<{ kind: string; phish: number; flagged: number }>;
  missed: Array<Pick<LabelledRun, 'id' | 'url' | 'kind' | 'brand' | 'note'>>;
  falsePositives: Array<Pick<LabelledRun, 'id' | 'url' | 'verdict' | 'note'> & { indicators: string[] }>;
}

const RANK: Record<string, number> = { info: 0, low: 1, medium: 2, high: 3 };
const atLeast = (r: LabelledRun, min: number) => r.indicators.some((i) => (RANK[i.severity] ?? 0) >= min);

export function evaluate(rows: LabelledRun[]): Evaluation {
  const scored = rows.filter((r) => r.verdict !== 'unsure');
  const phish = scored.filter((r) => r.verdict === 'phish');
  const other = scored.filter((r) => r.verdict !== 'phish');
  const score = (pred: (r: LabelledRun) => boolean): Score => ({
    flaggedPhish: phish.filter(pred).length,
    flaggedOther: other.filter(pred).length,
  });
  const ids = [...new Set(scored.flatMap((r) => r.indicators.map((i) => i.id)))].sort();
  const kinds = [...new Set(phish.map((r) => r.kind || '(none)'))].sort();
  return {
    phish: phish.length,
    other: other.length,
    unsure: rows.length - scored.length,
    thresholds: [
      { name: 'high', ...score((r) => atLeast(r, 3)) },
      { name: 'medium and up', ...score((r) => atLeast(r, 2)) },
      { name: 'any, info included', ...score((r) => r.indicators.length > 0) },
    ],
    indicators: ids.map((id) => ({ id, ...score((r) => r.indicators.some((i) => i.id === id)) })),
    byKind: kinds.map((kind) => {
      const of = phish.filter((r) => (r.kind || '(none)') === kind);
      return { kind, phish: of.length, flagged: of.filter((r) => atLeast(r, 2)).length };
    }),
    missed: phish.filter((r) => !atLeast(r, 2)).map(({ id, url, kind, brand, note }) => ({ id, url, kind, brand, note })),
    falsePositives: other.filter((r) => atLeast(r, 2)).map(({ id, url, verdict, note, indicators }) => ({
      id, url, verdict, note, indicators: indicators.filter((i) => (RANK[i.severity] ?? 0) >= 2).map((i) => `${i.id}/${i.severity}`),
    })),
  };
}
