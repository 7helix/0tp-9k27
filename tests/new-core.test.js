import test from 'node:test';
import assert from 'node:assert/strict';
import { alphaTotp, STEAM_ALPHABET, entropy, groupSecret, formatCode, maskCode, normalizeNumericInput, DriftTracker, randomBytes, verifyTotp, totp } from '../src/index.js';

test('alpha TOTP: deterministic per step, right alphabet/length, changes across steps', () => {
  const k = randomBytes(20); const t = 1_700_000_000_000;
  const a = alphaTotp(k, { time: t });
  assert.equal(a, alphaTotp(k, { time: t + 5_000 }));
  assert.match(a, new RegExp(`^[${STEAM_ALPHABET}]{5}$`));
  assert.notEqual(a, alphaTotp(k, { time: t + 30_000 }));
  assert.equal(alphaTotp(k, { time: t, length: 8 }).length, 8);
});

test('entropy maths', () => {
  assert.equal(Math.round(entropy.codeSpaceBits(10, 6) * 10) / 10, 19.9);
  assert.equal(entropy.successProbability({ attempts: 5 }), 5e-6);
  assert.equal(entropy.successProbability({ attempts: 5, validCodes: 3 }), 15e-6); // TOTP +/-1 window
  assert.equal(entropy.minLengthFor({ attempts: 5, target: 1e-8 }), 9);
  assert.equal(entropy.successProbability({ attempts: 1e9 }), 1);
  assert.equal(entropy.compare().length, 5);
});

test('formatting helpers', () => {
  assert.equal(groupSecret('JBSWY3DPEHPK3PXP'), 'JBSW Y3DP EHPK 3PXP');
  assert.equal(formatCode('123456'), '123 456'); assert.equal(formatCode('12345678'), '1234 5678');
  assert.equal(maskCode('123456'), '****56');
});
test('numeric input normalisation across scripts', () => {
  assert.equal(normalizeNumericInput(' 123-456 '), '123456');
  assert.equal(normalizeNumericInput('१२३४५६'), '123456');      // Devanagari
  assert.equal(normalizeNumericInput('౧౨౩౪౫౬'), '123456');      // Telugu
  assert.equal(normalizeNumericInput('١٢٣٤٥٦'), '123456');      // Arabic-Indic
  assert.equal(normalizeNumericInput('１２３４５６'), '123456');  // full-width
});

test('drift tracker suggests an offset only for a steady, non-zero drift', () => {
  const d = new DriftTracker({ samples: 3 });
  d.record('u', -1); d.record('u', -1); assert.equal(d.suggestedOffset('u'), 0);
  d.record('u', -1); assert.equal(d.suggestedOffset('u'), -1);
  d.record('u', 0); assert.equal(d.suggestedOffset('u'), 0);
  // integration: a phone 1 step behind verifies with delta -1, then the offset centres it
  const k = randomBytes(20); const now = 1_700_000_000_000; const phone = totp(k, { time: now - 30_000 });
  assert.equal(verifyTotp(k, phone, { time: now }).delta, -1);
  assert.equal(verifyTotp(k, phone, { time: now + -1 * 30_000, window: 0 }).delta, 0);
});
