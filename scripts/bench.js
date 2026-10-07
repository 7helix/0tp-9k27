#!/usr/bin/env node
// Rough micro-benchmarks. The numbers depend on the machine, so use them to spot regressions
// between runs on the same box rather than to compare computers.
import { hotp, totp, verifyTotp, ChallengeOtp, MemoryStore, scryptHash, randomBytes } from '../src/index.js';

async function bench(name, iterations, fn) {
  const start = process.hrtime.bigint();
  for (let i = 0; i < iterations; i++) await fn(i);
  const ms = Number(process.hrtime.bigint() - start) / 1e6;

  const perSecond = (iterations / (ms / 1000)).toFixed(0).padStart(9);
  console.log(`${name.padEnd(28)} ${perSecond} ops/s   (${(ms / iterations).toFixed(3)} ms/op)`);
}

const secret = randomBytes(20);
const challenge = new ChallengeOtp({ store: new MemoryStore(), pepper: 'p'.repeat(32) });

await bench('hotp', 50_000, (i) => hotp(secret, i));
await bench('totp', 50_000, () => totp(secret));
await bench('verifyTotp (window 1)', 20_000, () => verifyTotp(secret, '000000'));
await bench('challenge issue', 10_000, (i) => challenge.issue({ userId: `u${i % 100}`, purpose: 'p' }));
await bench('scrypt hash (backup code)', 20, () => scryptHash('ABCDEFGHJK'));
