import test from 'node:test';
import assert from 'node:assert/strict';
import { decodeCbor, encodeCbor, WebAuthn, MemoryStore, createServer, OtpService, MemoryProvider, randomBytes } from '../src/index.js';
import { FakeAuthenticator } from './helpers/fake-authenticator.js';

test('CBOR: RFC 8949 Appendix A vectors (encode + decode)', () => {
  const vectors = [[0, '00'], [1, '01'], [23, '17'], [24, '1818'], [100, '1864'], [1000, '1903e8'], [1000000, '1a000f4240'], [-1, '20'], [-100, '3863'],
    ['', '60'], ['a', '6161'], ['IETF', '6449455446'], [[], '80'], [[1, 2, 3], '83010203'], [new Map([[1, 2], [3, 4]]), 'a201020304'], [false, 'f4'], [true, 'f5'], [null, 'f6'],
    [Buffer.from('01020304', 'hex'), '4401020304'], [[1, [2, 3], [4, 5]], '8301820203820405']];
  for (const [value, hex] of vectors) {
    assert.equal(encodeCbor(value).toString('hex'), hex, `encode ${hex}`);
    assert.deepEqual(decodeCbor(Buffer.from(hex, 'hex')), value, `decode ${hex}`);
  }
});
test('CBOR decoder rejects hostile input quickly', () => {
  const bad = ['1818ff', '5a00ffffff00', '9fff', 'bf6161ff', '1b8000000000000000', 'a2010101', '61ff', '00ff', 'f97e00', '5f', '7f6161ff', 'ff', '', '9b0000000100000000'];
  for (const hex of bad) assert.throws(() => decodeCbor(Buffer.from(hex, 'hex')), Error, hex);
  assert.throws(() => decodeCbor(Buffer.from('a201010103', 'hex')), /duplicate/);   // {1:1, 1:3}
  assert.deepEqual(decodeCbor(Buffer.from('a201010203', 'hex')), new Map([[1, 1], [2, 3]])); // distinct keys are fine
  assert.throws(() => decodeCbor(Buffer.from('81'.repeat(40) + '00', 'hex')), /too deep/);
});

const make = (o = {}) => new WebAuthn({ store: new MemoryStore(), rpId: 'example.com', rpName: 'Example', origins: ['https://example.com'], ...o });

for (const alg of ['ES256', 'EdDSA', 'RS256']) {
  test(`WebAuthn full lifecycle with ${alg}: register, authenticate, counter advances`, async () => {
    const wa = make(); const dev = new FakeAuthenticator({ alg, backupEligible: true });
    const reg = await wa.startRegistration({ userId: 'u1', userName: 'alice@example.com' });
    assert.equal(reg.options.attestation, 'none'); assert.equal(reg.options.authenticatorSelection.userVerification, 'required');
    assert.ok(!JSON.stringify(reg.options.user).includes('alice@example.com') || reg.options.user.name === 'alice@example.com');
    assert.notEqual(reg.options.user.id, 'u1', 'user handle is opaque');
    const done = await wa.finishRegistration({ userId: 'u1', response: dev.create(reg.options) });
    assert.equal(done.ok, true, JSON.stringify(done)); assert.equal(done.backupEligible, true);
    assert.equal((await wa.listCredentials('u1')).length, 1);
    for (let i = 0; i < 3; i++) {
      const a = await wa.startAuthentication({ userId: 'u1' });
      const res = await wa.finishAuthentication({ userId: 'u1', response: dev.get(a.options) });
      assert.equal(res.ok, true, JSON.stringify(res)); assert.equal(res.userVerified, true);
    }
  });
}

test('WebAuthn registration attacks', async () => {
  const cases = [
    ['wrong origin (phishing site)', { origin: 'https://examp1e.com' }, 'origin_mismatch'],
    ['wrong challenge', { challenge: 'AAAA' }, 'challenge_mismatch'],
    ['wrong ceremony type', { type: 'webauthn.get' }, 'wrong_type'],
    ['wrong rpId hash', { rpId: 'evil.com' }, 'rp_id_mismatch'],
    ['no user presence', { flags: 0x44 | 0x00 & 0 }, 'user_not_present'],
    ['no user verification', { flags: 0x41 }, 'user_not_verified'],
    ['packed attestation unsupported', { fmt: 'packed', attStmt: [['alg', -7]] }, 'unsupported_attestation'],
    ['cross-origin iframe', { crossOrigin: true }, 'cross_origin'],
  ];
  for (const [name, override, reason] of cases) {
    const wa = make(); const dev = new FakeAuthenticator();
    const reg = await wa.startRegistration({ userId: 'u', userName: 'x' });
    const r = await wa.finishRegistration({ userId: 'u', response: dev.create(reg.options, override) });
    assert.deepEqual([name, r.ok, r.reason], [name, false, reason]);
  }
  // wrong origin allowed only when configured
  const wa = make({ origins: ['https://example.com', 'https://app.example.com'] }); const dev = new FakeAuthenticator({ origin: 'https://app.example.com' });
  const reg = await wa.startRegistration({ userId: 'u', userName: 'x' });
  assert.equal((await wa.finishRegistration({ userId: 'u', response: dev.create(reg.options) })).ok, true);
});

test('WebAuthn registration: challenge single-use, expiry, duplicate credential, id mismatch, none pending', async () => {
  const c = { t: 1_000_000 }; const wa = make({ clock: () => c.t, store: new MemoryStore({ clock: () => c.t }) }); const dev = new FakeAuthenticator();
  assert.equal((await wa.finishRegistration({ userId: 'u', response: dev.create({ challenge: 'x' }) })).reason, 'no_active_challenge');
  const reg = await wa.startRegistration({ userId: 'u', userName: 'x' });
  const resp = dev.create(reg.options);
  assert.equal((await wa.finishRegistration({ userId: 'u', response: { ...resp, id: 'AAAA' } })).reason, 'id_mismatch');
  assert.equal((await wa.finishRegistration({ userId: 'u', response: resp })).reason, 'no_active_challenge', 'challenge was consumed by the failed try');
  const reg2 = await wa.startRegistration({ userId: 'u', userName: 'x' });
  c.t += 400_000; assert.equal((await wa.finishRegistration({ userId: 'u', response: dev.create(reg2.options) })).reason, 'no_active_challenge');
  const reg3 = await wa.startRegistration({ userId: 'u', userName: 'x' });
  assert.equal((await wa.finishRegistration({ userId: 'u', response: dev.create(reg3.options) })).ok, true);
  const reg4 = await wa.startRegistration({ userId: 'other', userName: 'y' });
  assert.equal((await wa.finishRegistration({ userId: 'other', response: dev.create(reg4.options) })).reason, 'credential_exists', 'same authenticator cannot be bound to two accounts');
  assert.equal((await wa.startRegistration({ userId: 'u', userName: 'x' })).options.excludeCredentials.length, 1);
});

test('WebAuthn authentication attacks', async () => {
  const setup = async () => { const wa = make(); const dev = new FakeAuthenticator(); const r = await wa.startRegistration({ userId: 'u', userName: 'x' }); await wa.finishRegistration({ userId: 'u', response: dev.create(r.options) }); return { wa, dev }; };
  const cases = [
    ['phishing origin', { origin: 'https://example.com.evil.io' }, 'origin_mismatch'],
    ['stale/foreign challenge', { challenge: 'AAAA' }, 'challenge_mismatch'],
    ['corrupt signature', { corruptSignature: true }, 'bad_signature'],
    ['wrong rpId', { rpId: 'evil.com' }, 'rp_id_mismatch'],
    ['missing UV', { flags: 0x01 }, 'user_not_verified'],
    ['missing UP', { flags: 0x04 }, 'user_not_present'],
    ['create-type used as assertion', { type: 'webauthn.create' }, 'wrong_type'],
  ];
  for (const [name, o, reason] of cases) {
    const { wa, dev } = await setup(); const a = await wa.startAuthentication({ userId: 'u' });
    const r = await wa.finishAuthentication({ userId: 'u', response: dev.get(a.options, o) });
    assert.deepEqual([name, r.ok, r.reason], [name, false, reason]);
  }
  const { wa, dev } = await setup();
  // replay: same assertion twice
  let a = await wa.startAuthentication({ userId: 'u' }); const resp = dev.get(a.options);
  assert.equal((await wa.finishAuthentication({ userId: 'u', response: resp })).ok, true);
  assert.equal((await wa.finishAuthentication({ userId: 'u', response: resp })).reason, 'no_active_challenge');
  // parallel replay of one assertion: exactly one wins
  a = await wa.startAuthentication({ userId: 'u' }); const r2 = dev.get(a.options);
  const results = await Promise.all(Array.from({ length: 10 }, () => wa.finishAuthentication({ userId: 'u', response: r2 })));
  assert.equal(results.filter((r) => r.ok).length, 1);
  // cloned authenticator: counter goes backwards
  a = await wa.startAuthentication({ userId: 'u' });
  assert.equal((await wa.finishAuthentication({ userId: 'u', response: dev.get(a.options, { signCount: 1 }) })).reason, 'sign_count_rollback');
  // other user's credential / unknown credential
  const intruder = new FakeAuthenticator(); a = await wa.startAuthentication({ userId: 'u' });
  assert.equal((await wa.finishAuthentication({ userId: 'u', response: intruder.get(a.options) })).reason, 'unknown_credential');
  assert.equal((await wa.startAuthentication({ userId: 'ghost' })).reason, 'no_credentials');
});

test('WebAuthn: synced passkeys with counter 0 are accepted; credential removal works', async () => {
  const wa = make(); const dev = new FakeAuthenticator({ backupEligible: true });
  const r = await wa.startRegistration({ userId: 'u', userName: 'x' }); await wa.finishRegistration({ userId: 'u', response: dev.create(r.options) });
  for (let i = 0; i < 2; i++) { const a = await wa.startAuthentication({ userId: 'u' }); assert.equal((await wa.finishAuthentication({ userId: 'u', response: dev.get(a.options, { signCount: 0 }) })).ok, true); }
  const [{ id }] = await wa.listCredentials('u');
  assert.equal((await wa.removeCredential({ userId: 'u', credentialId: id })).ok, true);
  assert.equal((await wa.removeCredential({ userId: 'u', credentialId: id })).ok, false);
  assert.equal((await wa.startAuthentication({ userId: 'u' })).reason, 'no_credentials');
  // the freed credential can be registered again
  const r2 = await wa.startRegistration({ userId: 'u', userName: 'x' });
  assert.equal((await wa.finishRegistration({ userId: 'u', response: dev.create(r2.options) })).ok, true);
});

test('WebAuthn never throws on garbage input', async () => {
  const wa = make(); const dev = new FakeAuthenticator();
  const r = await wa.startRegistration({ userId: 'u', userName: 'x' }); await wa.finishRegistration({ userId: 'u', response: dev.create(r.options) });
  const junk = ['', 'AAAA', '////', 'not base64!!', 'x'.repeat(20_000), b64(randomBytes(10)), b64(randomBytes(300)), b64(Buffer.from('a10101', 'hex'))];
  function b64(b) { return Buffer.from(b).toString('base64url'); }
  for (const j of junk) {
    const reg = await wa.startRegistration({ userId: 'v', userName: 'x' });
    const a = await wa.finishRegistration({ userId: 'v', response: { id: j, clientDataJSON: j, attestationObject: j } });
    assert.equal(a.ok, false);
    const auth = await wa.startAuthentication({ userId: 'u' });
    const b = await wa.finishAuthentication({ userId: 'u', response: { id: j, clientDataJSON: j, authenticatorData: j, signature: j } });
    assert.equal(b.ok, false);
  }
  for (const weird of [null, undefined, 5, [], { id: 5 }]) {
    await wa.startAuthentication({ userId: 'u' });
    assert.equal((await wa.finishAuthentication({ userId: 'u', response: weird })).ok, false);
  }
});

test('WebAuthn rate limits ceremony starts; constructor validates config', async () => {
  const wa = make(); let limited = 0;
  for (let i = 0; i < 12; i++) if ((await wa.startRegistration({ userId: 'spam', userName: 'x' })).reason === 'rate_limited') limited++;
  assert.equal(limited, 2);
  assert.throws(() => new WebAuthn({ store: new MemoryStore() }), /rpId/);
});

test('WebAuthn over HTTP routes (auth required, UV policy relaxed option)', async () => {
  const wa = make({ requireUV: false });
  const svc = new OtpService({ store: new MemoryStore(), masterKey: randomBytes(32), pepper: 'w'.repeat(40), provider: new MemoryProvider() });
  const server = createServer(svc, { apiKey: 'k', webauthn: wa });
  await new Promise((r) => server.listen(0, '127.0.0.1', r)); const base = `http://127.0.0.1:${server.address().port}`;
  const post = (p, b, key = 'k') => fetch(base + p, { method: 'POST', headers: { 'x-api-key': key }, body: JSON.stringify(b) }).then(async (r) => ({ status: r.status, body: await r.json() }));
  try {
    const dev = new FakeAuthenticator({ uv: false });
    assert.equal((await post('/webauthn/auth/start', { userId: 'u' }, 'bad')).status, 401);
    const start = await post('/webauthn/register/start', { userId: 'u', userName: 'alice' });
    assert.equal(start.body.ok, true);
    assert.equal((await post('/webauthn/register/finish', { userId: 'u', response: dev.create(start.body.options) })).body.ok, true);
    assert.equal((await post('/webauthn/register/finish', { userId: 'u', response: 'nope' })).status, 400);
    const a = await post('/webauthn/auth/start', { userId: 'u' });
    const fin = await post('/webauthn/auth/finish', { userId: 'u', response: dev.get(a.body.options) });
    assert.deepEqual([fin.status, fin.body.ok], [200, true]);
  } finally { server.close(); server.closeAllConnections?.(); }
});
