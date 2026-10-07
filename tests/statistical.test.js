import test from 'node:test';
import assert from 'node:assert/strict';
import { randomDigits, randomFromAlphabet, UNAMBIGUOUS } from '../src/index.js';

// Chi-square uniformity sanity checks. Thresholds sit far above the 0.001 critical value, so a
// correct CSPRNG essentially never fails, while a biased generator (e.g. Math.random()%10 bugs) would.
function chi2(counts, expected) { return counts.reduce((s, c) => s + (c - expected) ** 2 / expected, 0); }

test('randomDigits is uniform over 0-9 (200k samples)', () => {
  const N = 200_000, counts = Array(10).fill(0);
  for (const ch of randomDigits(N)) counts[Number(ch)]++;
  assert.ok(chi2(counts, N / 10) < 40, `chi2 too high: ${chi2(counts, N / 10)}`);
});
test('randomFromAlphabet is uniform over the unambiguous alphabet', () => {
  const N = 150_000, counts = new Map([...UNAMBIGUOUS].map((c) => [c, 0]));
  for (const ch of randomFromAlphabet(UNAMBIGUOUS, N)) counts.set(ch, counts.get(ch) + 1);
  assert.ok(chi2([...counts.values()], N / UNAMBIGUOUS.length) < 70);
});
test('no repeated 6-digit codes in 5k draws beyond birthday expectation', () => {
  const seen = new Set();
  let dup = 0;
  for (let i = 0; i < 5000; i++) { const c = randomDigits(6); if (seen.has(c)) dup++; seen.add(c); }
  assert.ok(dup < 60, `unexpected duplicate count ${dup}`); // expected ~12
});
test('leading zeros are preserved (a classic OTP bug)', () => {
  let z = 0;
  for (let i = 0; i < 20_000; i++) if (randomDigits(6)[0] === '0') z++;
  assert.ok(z > 1500 && z < 2500);
});
