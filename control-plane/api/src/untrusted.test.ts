import { test } from 'node:test';
import assert from 'node:assert/strict';
import { insideDir, isPng, isRunId, summarize, validateSubmission } from './untrusted';

test('validateSubmission', () => {
  assert.deepEqual(validateSubmission({ url: 'https://example.com/a?b' }), { url: 'https://example.com/a?b', profile: '' });
  assert.equal(validateSubmission({ url: 'http://x.test/', profile: 'stealth' }).profile, 'stealth');
  for (const bad of [null, 'x', {}, { url: '' }, { url: 'javascript:alert(1)' }, { url: 'file:///etc/passwd' }, { url: 'https://x.test/a b' },
    { url: 'https://x.test/\u0000' }, { url: 'x'.repeat(3000) }, { url: '/relative' }, { url: 'https://x.test/', profile: '../x' }, { url: 'https://x.test/', profile: 5 }]) {
    assert.throws(() => validateSubmission(bad), `accepted ${JSON.stringify(bad)?.slice(0, 40)}`);
  }
});

test('insideDir', () => {
  assert.equal(insideDir('/runs', 'a', 'guest/screenshot.png'), '/runs/a/guest/screenshot.png');
  for (const bad of [['..', 'etc'], ['/etc/passwd'], ['a/../../x'], ['']]) assert.throws(() => insideDir('/runs', ...bad));
});

test('isRunId and isPng', () => {
  assert.ok(isRunId('01a13633-824b-7af2-940f-801e6ccd5a87'));
  for (const bad of ['../x', '01a13633-824b-4af2-940f-801e6ccd5a87', '', 7]) assert.ok(!isRunId(bad));
  assert.ok(isPng(Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0])));
  assert.ok(!isPng(Buffer.from('<svg onload=alert(1)>')));
});

test('summarize tolerates junk', () => {
  assert.equal(summarize(null).requests, 0);
  const s = summarize({ run: { status: 'completed' }, navigation: { finalUrl: 'https://x.test/', title: 't'.repeat(1000), redirectChain: [{}, {}] },
    network: { requests: [1, 2, 3], domains: [{ registrable: 'x.test' }, { registrable: 5 }] }, reconciliation: { consistent: true }, gaps: ['a'] });
  assert.equal((s.title as string).length, 300);
  assert.deepEqual(s.domains, ['x.test', '']);
  assert.equal(s.redirects, 2);
  assert.equal(s.consistent, true);
});
