import test from 'node:test';
import assert from 'node:assert/strict';
import {
  shamir,
  AuditLog,
  AuditCheckpointer,
  withMinDuration,
  ProofOfWork,
  haversineKm,
  impossibleTravel,
  exportSecrets,
  importSecrets,
  ChallengeOtp,
  MemoryStore,
  randomBytes,
  wipe,
} from '../src/index.js';
import { solve } from '../src/security/pow.js';

test('shamir: any k of n reconstruct; k-1 do not; wrong sets rejected', () => {
  const secret = randomBytes(32);
  const { shares, fingerprint } = shamir.split(secret, 5, 3);
  assert.equal(shares.length, 5);
  for (const pick of [[0, 1, 2], [4, 2, 0], [1, 3, 4], [0, 1, 2, 3, 4]])
    assert.deepEqual(shamir.combine(pick.map((i) => shares[i]), { fingerprint }), secret);
  assert.throws(() => shamir.combine([shares[0], shares[1]]), /need at least 3/);
  // With only k-1 shares you can still run the math, but the result is unrelated to the secret:
  const twoBad = shamir.combine([shares[0], shares[1], shares[2]].map((s, i) => (i < 2 ? s : shamir.split(secret, 5, 3).shares[2])));
  assert.notDeepEqual(twoBad, secret);
  assert.throws(() => shamir.combine([shares[0], shares[0], shares[1]]), /duplicate/);
  assert.throws(
    () => shamir.combine([shares[0], shares[1], shares[2].replace(/.$/, (c) => (c === '0' ? '1' : '0'))]),
    /checksum/,
  );
  assert.throws(() => shamir.combine(shares.slice(0, 3), { fingerprint: 'deadbeefdeadbeef' }), /fingerprint/);
  assert.throws(() => shamir.split(secret, 3, 5));
  assert.throws(() => shamir.split(secret, 300, 2));
  assert.throws(() => shamir.split(Buffer.alloc(0), 3, 2));
  assert.throws(() => shamir.combine(['nonsense']), /malformed/);
});
test('shamir: single-byte secrets are uniformly hidden by k-1 shares (statistical sanity)', () => {
  // For k=2, a single share's y value must be uniform regardless of the secret byte.
  const counts = new Array(256).fill(0);
  for (let i = 0; i < 25_600; i++) { const { shares } = shamir.split(Buffer.from([0x42]), 3, 2); counts[parseInt(shares[0].split('-')[3], 16)]++; }
  const chi = counts.reduce((s, c) => s + (c - 100) ** 2 / 100, 0);
  assert.ok(chi < 400, `chi2=${chi}`); // df=255, p=0.001 critical ~330; generous bound
});

test('audit checkpoints detect truncation, rewriting and forged signatures', () => {
  const a = new AuditLog();
  for (let i = 0; i < 6; i++) a.append(`e${i}`, { userId: 'u' });
  const { publicKey, privateKey } = AuditCheckpointer.generateKeys();
  const cp = new AuditCheckpointer({ privateKey }).checkpoint(a.entries.slice(0, 4));
  assert.deepEqual(AuditCheckpointer.verify(cp, publicKey, a.entries), { ok: true });
  assert.equal(AuditCheckpointer.verify(cp, publicKey, a.entries.slice(0, 2)).reason, 'truncated');
  const rewritten = new AuditLog();
  for (let i = 0; i < 6; i++) rewritten.append(`e${i}`, { userId: i === 1 ? 'evil' : 'u' });
  assert.equal(AuditCheckpointer.verify(cp, publicKey, rewritten.entries).reason, 'history_rewritten');
  assert.equal(AuditCheckpointer.verify({ ...cp, seq: 5 }, publicKey, a.entries).reason, 'bad_signature');
  const other = AuditCheckpointer.generateKeys();
  assert.equal(AuditCheckpointer.verify(cp, other.publicKey, a.entries).reason, 'bad_signature');
});

test('min-duration wrapper pads fast paths, propagates errors and results', async () => {
  const t0 = Date.now();
  assert.equal(await withMinDuration(60, async () => 'x'), 'x');
  assert.ok(Date.now() - t0 >= 55);
  await assert.rejects(withMinDuration(20, async () => { throw new Error('boom'); }), /boom/);
  assert.equal(await withMinDuration(0, async () => 7), 7);
});

test('proof of work: solve, verify, tamper, wrong resource, single use, expiry', async () => {
  const c = { t: 1_000_000 };
  const key = randomBytes(32);
  const pow = new ProofOfWork({ key, store: new MemoryStore({ clock: () => c.t }), clock: () => c.t });
  const { challenge, bits } = pow.issue({ bits: 12, resource: '/otp/send' });
  const nonce = solve(challenge, bits);
  assert.equal(
    (await pow.verify({ challenge, nonce: 'x'.repeat(3), resource: '/otp/send' })).reason,
    'insufficient_work',
  );
  assert.equal((await pow.verify({ challenge, nonce, resource: '/other' })).reason, 'wrong_resource');
  assert.equal((await pow.verify({ challenge: challenge + 'A', nonce, resource: '/otp/send' })).ok, false);
  assert.equal((await pow.verify({ challenge, nonce, resource: '/otp/send' })).ok, true);
  assert.equal((await pow.verify({ challenge, nonce, resource: '/otp/send' })).reason, 'already_used');
  const c2 = pow.issue({ bits: 8 });
  c.t += 500_000;
  assert.equal((await pow.verify({ challenge: c2.challenge, nonce: solve(c2.challenge, 8) })).ok, false);
  assert.throws(() => solve(challenge, 40, { maxIterations: 100 }), /no solution/);
});

test('geo: haversine and impossible travel', () => {
  const ny = { lat: 40.7128, lon: -74.006 }, london = { lat: 51.5074, lon: -0.1278 };
  const km = haversineKm(ny, london);
  assert.ok(km > 5540 && km < 5600, String(km));
  assert.equal(impossibleTravel({ ...ny, t: 0 }, { ...london, t: 3_600_000 }), true);
  assert.equal(impossibleTravel({ ...ny, t: 0 }, { ...london, t: 10 * 3_600_000 }), false);
  assert.equal(impossibleTravel({ lat: 17.38, lon: 78.48, t: 0 }, { lat: 17.45, lon: 78.4, t: 1000 }), false); // same city = GeoIP noise
});

test('encrypted export: roundtrip, wrong passphrase, tamper, weak passphrase, KDF DoS guard', () => {
  const data = { u1: { secret: 'JBSWY3DPEHPK3PXP' }, u2: { secret: 'KRSXG5CTMVRXEZLU' } };
  const env = exportSecrets(data, 'correct horse battery');
  assert.deepEqual(importSecrets(env, 'correct horse battery'), data);
  assert.throws(() => importSecrets(env, 'wrong passphrase!!'), /wrong passphrase/);
  const bad = JSON.parse(env);
  bad.ct = bad.ct.replace(/^./, (x) => (x === 'A' ? 'B' : 'A'));
  assert.throws(() => importSecrets(JSON.stringify(bad), 'correct horse battery'), /wrong passphrase/);
  const swapped = JSON.parse(env);
  swapped.N = 2 ** 14; // parameters are authenticated
  assert.throws(() => importSecrets(JSON.stringify(swapped), 'correct horse battery'));
  const evil = JSON.parse(env);
  evil.N = 2 ** 30;
  assert.throws(() => importSecrets(JSON.stringify(evil), 'x'), /too expensive/);
  assert.throws(() => exportSecrets(data, 'short'), /at least 12/);
});

test('OTP input normalisation: non-Latin digits, spaces, dashes accepted', async () => {
  const store = new MemoryStore();
  const o = new ChallengeOtp({ store, pepper: 'p'.repeat(32) });
  const { code } = await o.issue({ userId: 'u', purpose: 'p' });
  const telugu = [...code].map((d) => String.fromCodePoint(0xc66 + Number(d))).join('');
  assert.equal((await o.verify({ userId: 'u', purpose: 'p', code: `${telugu.slice(0, 3)} ${telugu.slice(3)}` })).ok, true);
  const a = await o.issue({ userId: 'u', purpose: 'q', kind: 'alnum', length: 8 });
  assert.equal((await o.verify({ userId: 'u', purpose: 'q', code: `${a.code.slice(0, 4).toLowerCase()}-${a.code.slice(4)}` })).ok, true);
});
test('wipe zeroes buffers and ignores non-buffers', () => { const b = Buffer.from('secret'); wipe(b); assert.ok(b.every((x) => x === 0)); wipe('str'); wipe(null); });
