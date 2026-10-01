import test from 'node:test';
import assert from 'node:assert/strict';
import { base32Encode, base32Decode, hotp, verifyHotp, totp, verifyTotp, buildOtpauthUri, parseOtpauthUri, secretBox, randomBytes } from '../src/index.js';

test('base32 RFC 4648 vectors + roundtrip', () => {
  assert.equal(base32Encode(Buffer.from('foobar')), 'MZXW6YTBOI');
  assert.equal(base32Encode(Buffer.from('fo'), { padding: true }), 'MZXQ====');
  assert.equal(base32Decode('MZXW6YTBOI').toString(), 'foobar');
  const b = randomBytes(37);
  assert.deepEqual(base32Decode(base32Encode(b)), b);
  assert.throws(() => base32Decode('abc!'));
});

const S1 = Buffer.from('12345678901234567890');
test('HOTP RFC 4226 Appendix D vectors', () => {
  const exp = ['755224','287082','359152','969429','338314','254676','287922','162583','399871','520489'];
  exp.forEach((e, i) => assert.equal(hotp(S1, i), e));
});
test('HOTP look-ahead resync + no reuse', () => {
  const r = verifyHotp(S1, '359152', 0);
  assert.deepEqual(r, { valid: true, nextCounter: 3 });
  assert.equal(verifyHotp(S1, '359152', r.nextCounter).valid, false);
  assert.equal(verifyHotp(S1, '000000', 0).valid, false);
});

test('TOTP RFC 6238 vectors (SHA1/256/512, 8 digits)', () => {
  const S256 = Buffer.from('12345678901234567890123456789012');
  const S512 = Buffer.from('1234567890123456789012345678901234567890123456789012345678901234');
  const cases = [
    [59, '94287082', '46119246', '90693936'],
    [1111111109, '07081804', '68084774', '25091201'],
    [1111111111, '14050471', '67062674', '99943326'],
    [1234567890, '89005924', '91819424', '93441116'],
    [2000000000, '69279037', '90698825', '38618901'],
    [20000000000, '65353130', '77737706', '47863826'],
  ];
  for (const [t, a, b, c] of cases) {
    assert.equal(totp(S1, { time: t * 1000, digits: 8, algorithm: 'SHA1' }), a);
    assert.equal(totp(S256, { time: t * 1000, digits: 8, algorithm: 'SHA256' }), b);
    assert.equal(totp(S512, { time: t * 1000, digits: 8, algorithm: 'SHA512' }), c);
  }
});
test('TOTP window + replay protection', () => {
  const t = 1_700_000_000_000;
  const code = totp(S1, { time: t });
  const ok = verifyTotp(S1, code, { time: t + 30_000 }); // one step late: still ok
  assert.equal(ok.valid, true); assert.equal(ok.delta, -1);
  assert.equal(verifyTotp(S1, code, { time: t + 90_000 }).valid, false); // too old
  const replay = verifyTotp(S1, code, { time: t, lastUsedCounter: ok.counter });
  assert.deepEqual(replay, { valid: false, reason: 'replayed' });
});

test('otpauth URI build/parse', () => {
  const uri = buildOtpauthUri({ issuer: 'My App', account: 'a@b.com', secret: 'JBSWY3DPEHPK3PXP' });
  const p = parseOtpauthUri(uri);
  assert.equal(p.issuer, 'My App'); assert.equal(p.account, 'a@b.com'); assert.equal(p.secret, 'JBSWY3DPEHPK3PXP'); assert.equal(p.period, 30);
});

test('secret-box: roundtrip, tamper and AAD binding', () => {
  const k = randomBytes(32);
  const ct = secretBox.encrypt(k, Buffer.from('seed'), 'user1');
  assert.equal(secretBox.decrypt(k, ct, 'user1').toString(), 'seed');
  assert.throws(() => secretBox.decrypt(k, ct, 'user2'));
  const parts = ct.split('.'); parts[3] = parts[3].replace(/^./, (c) => (c === 'A' ? 'B' : 'A'));
  assert.throws(() => secretBox.decrypt(k, parts.join('.'), 'user1'));
});
