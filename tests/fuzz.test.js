import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { ChallengeOtp, MemoryStore, isUserId, isE164, isEmail, isOtpCode, normalizeNumericInput, base32Decode, parseOtpauthUri, signedToken, decodeCbor, parseAuthData, shamir, parseIp, parseCidr, createServer, OtpService, MemoryProvider, randomBytes } from '../src/index.js';

// Deterministic PRNG so any failure is reproducible (seed printed on failure).
const SEED = Number(process.env.FUZZ_SEED || 0xC0FFEE);
function rng(seed) { let a = seed >>> 0; return () => { a = (a + 0x6d2b79f5) >>> 0; let t = a; t = Math.imul(t ^ (t >>> 15), t | 1); t ^= t + Math.imul(t ^ (t >>> 7), t | 61); return ((t ^ (t >>> 14)) >>> 0) / 4294967296; }; }
const r = rng(SEED); const int = (n) => Math.floor(r() * n);
const pick = (a) => a[int(a.length)];
const UNI = ['\u0000', '\u202e', '😀', 'ℌ', '١', '౧', '\ufeff', '\n', '\t', ' ', '-', '.', '%', "'", '"', '<', '>', '\\', '/', 'é', '\ud800', 'Ａ'];
const rstr = (max = 40) => Array.from({ length: int(max) }, () => (r() < 0.5 ? String.fromCharCode(32 + int(95)) : pick(UNI))).join('');
const rbytes = (max = 64) => crypto.randomBytes(int(max));
const weird = () => pick([null, undefined, true, false, 0, -1, 1e308, NaN, '', rstr(), rstr(5000), [], [1, 2], {}, { a: { b: [1] } }, () => 1, Symbol.iterator.toString(), 12345678901234567890n.toString()]);
const tag = (s) => `seed=${SEED}: ${s}`;

test('fuzz: validators and normaliser never throw and return the right types', () => {
  for (let i = 0; i < 3000; i++) {
    const v = r() < 0.5 ? rstr(300) : weird();
    for (const f of [isUserId, isE164, isEmail, isOtpCode]) assert.equal(typeof f(v), 'boolean', tag(String(v).slice(0, 30)));
    assert.equal(typeof normalizeNumericInput(typeof v === 'symbol' ? 'x' : String(v)), 'string');
  }
});
test('fuzz: ChallengeOtp.verify with hostile codes never throws and never accepts garbage', async () => {
  const o = new ChallengeOtp({ store: new MemoryStore(), pepper: 'f'.repeat(32) });
  for (let i = 0; i < 400; i++) {
    const { code } = await o.issue({ userId: 'u', purpose: 'p', maxAttempts: 1000 });
    const guess = rstr(60); if (guess.normalize('NFKC').replace(/[\s-]/g, '') === code) continue;
    const res = await o.verify({ userId: 'u', purpose: 'p', code: guess });
    assert.equal(res.ok, false, tag(JSON.stringify(guess)));
  }
});
test('fuzz: base32 / otpauth / signed-token / shamir / ip parsers fail cleanly', () => {
  const key = randomBytes(32);
  for (let i = 0; i < 3000; i++) {
    const s = rstr(200);
    try { base32Decode(s); } catch (e) { assert.ok(e instanceof Error && /Base32/.test(e.message), tag(s)); }
    try { parseOtpauthUri(s); } catch (e) { assert.ok(e instanceof Error, tag(s)); }
    try { shamir.combine([s]); assert.fail('accepted garbage share'); } catch (e) { assert.ok(e instanceof Error); }
    assert.equal(signedToken.verify(key, s).ok, false, tag(s));
    assert.equal(signedToken.verify(key, `${rstr(30)}.${rstr(30)}`).ok, false);
    const ip = parseIp(s); assert.ok(ip === null || typeof ip.n === 'bigint');
    try { parseCidr(s); } catch (e) { assert.ok(e instanceof Error); }
  }
});
test('fuzz: CBOR / authData decoders terminate and throw ordinary errors on random bytes', () => {
  const t0 = Date.now();
  for (let i = 0; i < 20_000; i++) {
    const b = rbytes(120);
    try { decodeCbor(b); } catch (e) { assert.ok(e instanceof Error, tag(b.toString('hex'))); }
    try { parseAuthData(b); } catch (e) { assert.ok(e instanceof Error); }
    // structured mutation of a realistic prefix
    const mutated = Buffer.concat([Buffer.from('a563666d74646e6f6e65', 'hex'), b]);
    try { decodeCbor(mutated); } catch (e) { assert.ok(e instanceof Error); }
  }
  assert.ok(Date.now() - t0 < 10_000, 'decoder must not be slow on hostile input');
});
test('fuzz: HTTP API answers every hostile body with a 4xx/2xx - never a 500, never a hang', async () => {
  const svc = new OtpService({ store: new MemoryStore(), masterKey: randomBytes(32), pepper: 'f'.repeat(40), provider: new MemoryProvider() });
  const server = createServer(svc, { apiKey: 'k' }); await new Promise((res) => server.listen(0, '127.0.0.1', res));
  const base = `http://127.0.0.1:${server.address().port}`;
  const paths = ['/otp/send', '/otp/verify', '/totp/enroll', '/totp/confirm', '/totp/verify', '/backup/generate', '/backup/verify'];
  const statuses = new Map();
  try {
    for (let i = 0; i < 350; i++) {
      const path = pick(paths);
      const body = r() < 0.15 ? rstr(200) : r() < 0.3 ? JSON.stringify(weird()) : JSON.stringify({ userId: weird(), code: weird(), channel: weird(), to: weird(), account: weird(), ['__proto__']: weird(), constructor: { prototype: { x: 1 } } });
      const resp = await fetch(base + path, { method: 'POST', headers: { 'x-api-key': 'k', 'content-type': r() < 0.5 ? 'application/json' : 'text/plain' }, body });
      statuses.set(resp.status, (statuses.get(resp.status) || 0) + 1);
      await resp.text();
      assert.notEqual(resp.status, 500, tag(`${path} ${String(body).slice(0, 120)}`));
    }
    assert.equal({}.x, undefined, 'prototype was not polluted');
  } finally { server.close(); server.closeAllConnections?.(); }
  assert.ok(statuses.get(400) > 100, 'most garbage is rejected as 400');
});
