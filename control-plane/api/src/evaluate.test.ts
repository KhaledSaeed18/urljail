import { test } from 'node:test';
import assert from 'node:assert/strict';
import { evaluate, LabelledRun } from './evaluate';
import { validateLabel } from './untrusted';

const run = (verdict: string, ...ind: Array<[string, string]>): LabelledRun => ({
  id: Math.random().toString(), url: 'https://x.test/', verdict, kind: verdict === 'phish' ? 'credential' : '', brand: '', note: '',
  indicators: ind.map(([id, severity]) => ({ id, severity, brand: '' })),
});

test('evaluate counts per threshold and indicator; unsure is left out', () => {
  const e = evaluate([
    run('phish', ['brand-name-off-domain', 'high']),
    run('phish', ['form-on-free-hosting', 'medium']),
    run('phish', ['brand-presented-off-domain', 'info']),
    run('benign', ['form-on-free-hosting', 'medium']),
    run('real-site'),
    run('unsure', ['brand-name-off-domain', 'high']),
  ]);
  assert.equal(e.phish, 3);
  assert.equal(e.other, 2);
  assert.equal(e.unsure, 1);
  assert.deepEqual(e.thresholds.map((t) => [t.name, t.flaggedPhish, t.flaggedOther]),
    [['high', 1, 0], ['medium and up', 2, 1], ['any, info included', 3, 1]]);
  assert.deepEqual(e.indicators.find((i) => i.id === 'form-on-free-hosting'), { id: 'form-on-free-hosting', flaggedPhish: 1, flaggedOther: 1 });
  assert.equal(e.missed.length, 1);
  assert.deepEqual(e.falsePositives[0].indicators, ['form-on-free-hosting/medium']);
});

test('validateLabel accepts the known values and cleans the note', () => {
  assert.deepEqual(validateLabel({ verdict: 'phish', kind: 'lure', brand: 'dhl', note: ' parcel\nlure ' }),
    { verdict: 'phish', kind: 'lure', brand: 'dhl', note: 'parcel lure' });
  assert.deepEqual(validateLabel({ verdict: 'benign', kind: 'lure' }), { verdict: 'benign', kind: '', brand: '', note: '' });
  for (const bad of [{}, { verdict: 'evil' }, { verdict: 'phish', kind: 'x' }, { verdict: 'phish', brand: 'Bad Brand' }, { verdict: 'phish', note: 'x'.repeat(301) }]) {
    assert.throws(() => validateLabel(bad));
  }
});
