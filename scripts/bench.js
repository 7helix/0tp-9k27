#!/usr/bin/env node
// Quick micro-benchmarks. Numbers vary by machine; use them to spot regressions, not for marketing.
import { hotp, totp, verifyTotp, ChallengeOtp, MemoryStore, scryptHash, randomBytes } from '../src/index.js';

async function bench(name, n, fn) {
  const t0 = process.hrtime.bigint();
  for (let i = 0; i < n; i++) await fn(i);
  const ms = Number(process.hrtime.bigint() - t0) / 1e6;
  console.log(`${name.padEnd(28)} ${(n / (ms / 1000)).toFixed(0).padStart(9)} ops/s   (${(ms / n).toFixed(3)} ms/op)`);
}
const k = randomBytes(20); const store = new MemoryStore(); const o = new ChallengeOtp({ store, pepper: 'p'.repeat(32) });
await bench('hotp', 50_000, (i) => hotp(k, i));
await bench('totp', 50_000, () => totp(k));
await bench('verifyTotp (window 1)', 20_000, () => verifyTotp(k, '000000'));
await bench('challenge issue', 10_000, (i) => o.issue({ userId: `u${i % 100}`, purpose: 'p' }));
await bench('scrypt hash (backup code)', 20, () => scryptHash('ABCDEFGHJK'));
