import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import {
  WebAuthn,
  MemoryStore,
  normalizePolicy,
  extractCertAaguid,
  verifyRegistration,
  verifyChain,
  randomBytes,
} from '../src/index.js';
import { FakeAuthenticator } from './helpers/fake-authenticator.js';
import { makePki, haveOpenssl } from './helpers/test-pki.js';

const T = { skip: !haveOpenssl && 'openssl not available' };
const AAGUID = 'ee882879721c491397753dfcce97072a';
const OTHER_AAGUID = '2fc0579f811347eab116bb5a8db9202a';

async function register({ policy, auth, attestation, createOpts = {}, alg = 'ES256', now } = {}) {
  const wa = new WebAuthn({
    store: new MemoryStore(),
    rpId: 'example.com',
    origins: ['https://example.com'],
    attestation: policy,
    ...(now ? { clock: () => now } : {}),
  });
  const dev = auth ?? new FakeAuthenticator({ alg, aaguid: AAGUID });
  const start = await wa.startRegistration({ userId: 'u', userName: 'x' });
  const res = await wa.finishRegistration({
    userId: 'u',
    response: dev.create(start.options, { attestation, ...createOpts }),
  });
  return { wa, dev, res, start };
}

test('policy: validation catches misconfiguration at startup', T, () => {
  const pki = makePki();
  try {
    assert.deepEqual(normalizePolicy().formats, ['none']);
    assert.throws(() => normalizePolicy({ formats: ['tpm'] }), /subset/);
    assert.throws(() => normalizePolicy({ formats: [] }), /subset/);
    assert.throws(() => normalizePolicy({ trustAnchors: ['not a cert'] }), /invalid trust anchor/);
    assert.throws(() => normalizePolicy({ aaguidAllowlist: ['zz'] }), /invalid AAGUID/);
    assert.throws(
      () => normalizePolicy({ formats: ['packed'], requireTrustedChain: true }),
      /trust anchor/,
      'cannot demand trust with no anchors',
    );
    assert.throws(
      () => normalizePolicy({ formats: ['packed'], aaguidAllowlist: [AAGUID] }),
      /trust anchor/,
      'an allowlist implies trusted chains',
    );
    const ok = normalizePolicy({
      formats: ['packed'],
      trustAnchors: [pki.rootPem],
      aaguidAllowlist: ['EE882879-721C-4913-9775-3DFCCE97072A'],
    });
    assert.equal(ok.requireTrustedChain, true);
    assert.deepEqual(ok.aaguidAllowlist, [AAGUID]);
    const again = normalizePolicy(ok); // normalising twice is safe (policies get passed around)
    assert.deepEqual(
      [again.requireTrustedChain, again.aaguidAllowlist, again.trustAnchors.length],
      [true, [AAGUID], 1],
    );
    assert.throws(() => new WebAuthn({
      store: new MemoryStore(),
      rpId: 'e.com',
      origins: ['https://e.com'],
      attestation: { formats: ['bogus'] },
    }));
  } finally {
    pki.cleanup();
  }
});

test('default policy stays "none only": packed/u2f/self are refused unless enabled', async () => {
  const pki = makePki();
  try {
    assert.equal((await register()).res.ok, true);
    assert.equal(
      (await register({ attestation: { kind: 'packed', certKey: pki.leafKey, x5c: pki.x5c } })).res.reason,
      'unsupported_attestation',
    );
    assert.equal(
      (await register({ attestation: { kind: 'packed-self' } })).res.reason,
      'unsupported_attestation',
    );
    assert.equal(
      (await register({ policy: { formats: ['packed'] } })).res.reason,
      'unsupported_attestation',
      'none is refused when not listed',
    );
  } finally {
    pki.cleanup();
  }
}, T);

test('packed (certificate): trusted chain, with and without an intermediate; info recorded and survives login', T, async () => {
  for (const withIntermediate of [false, true]) {
    const pki = makePki({ aaguidHex: AAGUID, withIntermediate });
    try {
      const { res, wa, dev } = await register({
        policy: { formats: ['packed'], trustAnchors: [pki.rootPem], requireTrustedChain: true },
        attestation: { kind: 'packed', certKey: pki.leafKey, x5c: pki.x5c },
      });
      assert.equal(res.ok, true, JSON.stringify(res));
      assert.deepEqual(res.attestation, { format: 'packed', type: 'basic', trusted: true, aaguid: AAGUID });
      assert.deepEqual((await wa.listCredentials('u'))[0].attestation, res.attestation);
      const a = await wa.startAuthentication({ userId: 'u' });
      assert.equal((await wa.finishAuthentication({ userId: 'u', response: dev.get(a.options) })).ok, true);
      assert.equal(a.options.userVerification, 'required');
    } finally {
      pki.cleanup();
    }
  }
});

test('packed: untrusted root is accepted only when trust is not required, and is reported as untrusted', T, async () => {
  const mine = makePki(), theirs = makePki();
  try {
    const att = { kind: 'packed', certKey: theirs.leafKey, x5c: theirs.x5c };
    const strict = await register({
      policy: { formats: ['packed'], trustAnchors: [mine.rootPem], requireTrustedChain: true },
      attestation: att,
    });
    assert.equal(strict.res.reason, 'untrusted_attestation');
    const lax = await register({
      policy: { formats: ['packed'], trustAnchors: [mine.rootPem] },
      attestation: att,
    });
    assert.equal(lax.res.ok, true);
    assert.equal(lax.res.attestation.trusted, false);
    const noAnchors = await register({ policy: { formats: ['packed'] }, attestation: att });
    assert.equal(noAnchors.res.attestation.trusted, false);
  } finally {
    mine.cleanup(); theirs.cleanup();
  }
});

test('AAGUID allowlist / denylist restrict which hardware may enrol', T, async () => {
  const pki = makePki({ aaguidHex: AAGUID });
  try {
    const att = { kind: 'packed', certKey: pki.leafKey, x5c: pki.x5c };
    const base = { formats: ['packed'], trustAnchors: [pki.rootPem] };
    assert.equal(
      (await register({ policy: { ...base, aaguidAllowlist: [AAGUID] }, attestation: att })).res.ok,
      true,
    );
    assert.equal(
      (await register({ policy: { ...base, aaguidAllowlist: [OTHER_AAGUID] }, attestation: att })).res.reason,
      'aaguid_not_allowed',
    );
    assert.equal(
      (await register({ policy: { ...base, aaguidDenylist: [AAGUID] }, attestation: att })).res.reason,
      'aaguid_not_allowed',
    );
    // an allowlist must not be satisfiable with SELF-ASSERTED data: self attestation and untrusted certs are refused
    assert.equal(
      (await register({ policy: { ...base, aaguidAllowlist: [AAGUID] }, attestation: { kind: 'packed-self' } })).res.reason,
      'untrusted_attestation',
    );
    const rogue = makePki({ aaguidHex: AAGUID });
    try {
      const attestation = { kind: 'packed', certKey: rogue.leafKey, x5c: rogue.x5c };
      const result = await register({ policy: { ...base, aaguidAllowlist: [AAGUID] }, attestation });
      assert.equal(result.res.reason, 'untrusted_attestation', 'attacker with a matching AAGUID but a different CA');
    } finally {
      rogue.cleanup();
    }
    // 'none' attestation can never prove a model
    assert.equal(
      (await register({ policy: { formats: ['none', 'packed'], trustAnchors: [pki.rootPem], aaguidAllowlist: [AAGUID] } })).res.reason,
      'untrusted_attestation',
    );
  } finally {
    pki.cleanup();
  }
});

test('allowlist: a genuine certificate from the SAME trusted vendor for a model that is not listed is refused', T, async () => {
  const pki = makePki({ aaguidHex: AAGUID });
  try {
    const other = pki.issueLeaf({ aaguidHex: OTHER_AAGUID });
    const policy = { formats: ['packed'], trustAnchors: [pki.rootPem], aaguidAllowlist: [AAGUID] };
    const bad = await register({
      policy,
      auth: new FakeAuthenticator({ aaguid: OTHER_AAGUID }),
      attestation: { kind: 'packed', certKey: other.leafKey, x5c: other.x5c },
    });
    assert.equal(bad.res.reason, 'aaguid_not_allowed');
    const both = { ...policy, aaguidAllowlist: [AAGUID, OTHER_AAGUID] };
    const good = await register({
      policy: both,
      auth: new FakeAuthenticator({ aaguid: OTHER_AAGUID }),
      attestation: { kind: 'packed', certKey: other.leafKey, x5c: other.x5c },
    });
    assert.deepEqual(
      [good.res.ok, good.res.attestation.aaguid, good.res.attestation.trusted],
      [true, OTHER_AAGUID, true],
    );
  } finally {
    pki.cleanup();
  }
});

test('packed: certificate profile and signature attacks', T, async () => {
  const policy = (pki) => ({ formats: ['packed'], trustAnchors: [pki.rootPem], requireTrustedChain: true });
  async function run(pkiOptions, overrides = {}) {
    const pki = makePki(pkiOptions);
    try {
      const result = await register({
        policy: policy(pki),
        attestation: { kind: 'packed', certKey: pki.leafKey, x5c: pki.x5c, ...overrides },
      });
      return result.res.reason;
    } finally {
      pki.cleanup();
    }
  }
  assert.equal(
    await run({ aaguidHex: OTHER_AAGUID }),
    'aaguid_mismatch',
    'cert says one model, authenticator claims another',
  );
  assert.equal(await run({ aaguidHex: AAGUID, leafCA: true }), 'bad_attestation_cert', 'CA:TRUE leaf');
  assert.equal(await run({ aaguidHex: AAGUID, ou: 'Something Else' }), 'bad_attestation_cert', 'wrong OU');
  assert.equal(
    await run({ aaguidHex: AAGUID, criticalAaguid: true }),
    'bad_attestation',
    'critical AAGUID extension is forbidden',
  );
  assert.equal(await run({ aaguidHex: AAGUID }, { corruptSig: true }), 'bad_attestation_signature');
  assert.equal(
    await run({ aaguidHex: AAGUID }, { certKey: crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' }).privateKey }),
    'bad_attestation_signature',
    'signed with a key that is not in the cert',
  );
  assert.equal(
    await run({ aaguidHex: AAGUID, noAaguid: true }) === undefined,
    true,
    'AAGUID extension is optional',
  );
});

test('packed: certificate expiry is enforced against the injected clock', T, async () => {
  const pki = makePki({ days: 30 });
  try {
    const dev = new FakeAuthenticator({ aaguid: AAGUID });
    const wa = new WebAuthn({
      store: new MemoryStore(),
      rpId: 'example.com',
      origins: ['https://example.com'],
    });
    const start = await wa.startRegistration({ userId: 'u', userName: 'x' });
    const resp = dev.create(start.options, { attestation: { kind: 'packed', certKey: pki.leafKey, x5c: pki.x5c } });
    const attObj = Buffer.from(resp.attestationObject, 'base64url');
    const cd = Buffer.from(resp.clientDataJSON, 'base64url');
    const p = normalizePolicy({
      formats: ['packed'],
      trustAnchors: [pki.rootPem],
      requireTrustedChain: true,
    });
    const args = { clientDataJSON: cd, attestationObject: attObj, expectedChallenge: start.options.challenge, origins: ['https://example.com'], rpId: 'example.com', attestation: p };
    assert.equal(verifyRegistration({ ...args, now: Date.now() }).ok, true);
    assert.equal(
      verifyRegistration({ ...args, now: Date.now() + 90 * 86_400_000 }).reason,
      'untrusted_attestation',
      'leaf expired after 30 days',
    );
    assert.equal(
      verifyRegistration({ ...args, now: Date.now() - 86_400_000 * 2 }).reason,
      'untrusted_attestation',
      'not yet valid',
    );
  } finally {
    pki.cleanup();
  }
});

test('packed self attestation: accepted when allowed, never counts as trusted, tamper/alg-mismatch rejected', T, async () => {
  const p = { formats: ['packed'] };
  for (const alg of ['ES256', 'EdDSA', 'RS256']) {
    const r = await register({ policy: p, alg, attestation: { kind: 'packed-self' } });
    assert.equal(r.res.ok, true, `${alg}: ${JSON.stringify(r.res)}`);
    assert.deepEqual([r.res.attestation.type, r.res.attestation.trusted], ['self', null]);
  }
  assert.equal(
    (await register({ policy: { ...p, allowSelfAttestation: false }, attestation: { kind: 'packed-self' } })).res.reason,
    'self_attestation_not_allowed',
  );
  assert.equal(
    (await register({ policy: p, attestation: { kind: 'packed-self', corruptSig: true } })).res.reason,
    'bad_attestation_signature',
  );
  assert.equal(
    (await register({ policy: p, attestation: { kind: 'packed-self', statementAlg: -8 } })).res.reason,
    'alg_mismatch',
  );
});

test('fido-u2f: valid, trusted, tampered', T, async () => {
  const pki = makePki({ aaguidHex: AAGUID });
  try {
    const dev = () => new FakeAuthenticator({ alg: 'ES256' }); // u2f authenticators have an all-zero AAGUID
    const policy = { formats: ['fido-u2f'], trustAnchors: [pki.rootPem], requireTrustedChain: true };
    const ok = await register({
      policy,
      auth: dev(),
      attestation: { kind: 'fido-u2f', certKey: pki.leafKey, x5c: [pki.leafDer] },
    });
    assert.equal(ok.res.ok, true, JSON.stringify(ok.res));
    assert.deepEqual(
      ok.res.attestation,
      { format: 'fido-u2f', type: 'basic', trusted: true, aaguid: '0'.repeat(32) },
    );
    assert.equal(
      (await register({ policy, auth: dev(), attestation: { kind: 'fido-u2f', certKey: pki.leafKey, x5c: [pki.leafDer], corruptSig: true } })).res.reason,
      'bad_attestation_signature',
    );
    assert.equal(
      (await register({ policy: { ...policy, aaguidAllowlist: [AAGUID] }, auth: dev(), attestation: { kind: 'fido-u2f', certKey: pki.leafKey, x5c: [pki.leafDer] } })).res.reason,
      'aaguid_not_allowed',
      'u2f reports an all-zero AAGUID',
    );
    // U2F attestation only exists for P-256 credentials: an EdDSA credential claiming fido-u2f is refused
    const edReg = await register({
      policy: { formats: ['fido-u2f'] },
      auth: new FakeAuthenticator({ alg: 'EdDSA' }),
      createOpts: { fmt: 'fido-u2f', attStmt: [['sig', randomBytes(70)], ['x5c', [pki.leafDer]]] },
    });
    assert.equal(edReg.res.reason, 'bad_attestation');
  } finally {
    pki.cleanup();
  }
});

test('AAGUID extension parser and chain verifier: edge cases', T, () => {
  const pki = makePki({ aaguidHex: AAGUID, withIntermediate: true });
  try {
    assert.equal(extractCertAaguid(pki.leafDer), AAGUID);
    assert.equal(extractCertAaguid(pki.rootDer), null);
    assert.throws(
      () => extractCertAaguid(Buffer.concat([Buffer.from('060b2b06010401' + '82e51c010104', 'hex'), Buffer.from('0412041100', 'hex')])),
      /malformed/,
    );
    const mk = (d) => new crypto.X509Certificate(d);
    const now = Date.now();
    const root = mk(pki.rootDer), inter = mk(pki.intDer), leaf = mk(pki.leafDer);
    assert.equal(verifyChain([leaf, inter], [root], now), true);
    assert.equal(verifyChain([leaf], [root], now), false, 'leaf is not issued by the root directly');
    assert.equal(verifyChain([inter, leaf], [root], now), false, 'order matters');
    assert.equal(verifyChain([leaf, inter], [], now), false);
    assert.equal(verifyChain([leaf, inter], [leaf], now), false, 'an unrelated anchor');
    assert.equal(verifyChain([leaf], [leaf], now), true, 'pinning the leaf itself is allowed');
  } finally {
    pki.cleanup();
  }
});

test('attestation statements from hell never throw and never succeed', T, async () => {
  const pki = makePki();
  const p = normalizePolicy({ formats: ['packed', 'fido-u2f', 'none'], trustAnchors: [pki.rootPem] });
  try {
    const junkBytes = () => randomBytes(1 + Math.floor(Math.random() * 40));
    const stmts = [new Map(), new Map([['alg', 'x']]), new Map([['alg', -7], ['sig', junkBytes()], ['x5c', []]]), new Map([['alg', -7], ['sig', junkBytes()], ['x5c', [junkBytes()]]]),
      new Map([['alg', -7], ['sig', junkBytes()], ['x5c', 'str']]), new Map([['alg', 99], ['sig', junkBytes()]]), new Map([['ecdaaKeyId', junkBytes()], ['alg', -7], ['sig', junkBytes()]]),
      new Map([['sig', junkBytes()], ['x5c', [pki.leafDer, pki.leafDer, pki.leafDer, pki.leafDer, pki.leafDer, pki.leafDer, pki.leafDer]]]), new Map([['alg', -7], ['sig', junkBytes()], ['x5c', [pki.leafDer]]])];
    for (const fmt of ['packed', 'fido-u2f']) for (const stmt of stmts) {
      const dev = new FakeAuthenticator({ aaguid: AAGUID });
      const wa = new WebAuthn({
        store: new MemoryStore(),
        rpId: 'example.com',
        origins: ['https://example.com'],
        attestation: p,
      });
      const start = await wa.startRegistration({ userId: 'u', userName: 'x' });
      const resp = dev.create(start.options, { fmt, attStmt: [...stmt] });
      const r = await wa.finishRegistration({ userId: 'u', response: resp });
      assert.equal(r.ok, false, `${fmt} ${[...stmt.keys()]}`);
    }
  } finally {
    pki.cleanup();
  }
});
