import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { loadConfig, parseHmacKeys, randomBytes, signRequest } from '../src/index.js';
import { makePki, haveOpenssl } from './helpers/test-pki.js';
import { startServer, expectStartupFailure } from './helpers/server-process.js';

const hex32 = () => randomBytes(32).toString('hex');

// loadConfig warns when it makes up secrets in dev mode. Keep the test output clean.
function quiet(fn) {
  const original = console.warn;
  console.warn = () => {};
  try {
    return fn();
  } finally {
    console.warn = original;
  }
}

function productionEnv() {
  return {
    NODE_ENV: 'production',
    OTP_MASTER_KEY: hex32(),
    OTP_PEPPER: hex32(),
    OTP_API_KEY: 'k'.repeat(20),
    OTP_STORE_FILE: '/tmp/otpf-test-store.json',
  };
}

test('dev mode makes up secrets, production refuses to start without them', () => {
  const dev = quiet(() => loadConfig({}));
  assert.equal(dev.masterKey.length, 32);
  assert.ok(dev.apiKey);
  assert.equal(dev.port, 8080);
  assert.equal(dev.uniformErrors, true);

  for (const missing of ['OTP_MASTER_KEY', 'OTP_PEPPER', 'OTP_API_KEY']) {
    const env = productionEnv();
    delete env[missing];
    assert.throws(() => loadConfig(env), new RegExp(missing));
  }

  assert.throws(() => loadConfig({ ...productionEnv(), OTP_PEPPER: 'short' }), /PEPPER/);
  assert.throws(() => quiet(() => loadConfig({ OTP_MASTER_KEY: 'abcd' })), /64 hex/);
});

test('HMAC keys are parsed and validated', () => {
  const keys = parseHmacKeys(`backend-1:${hex32()}, backend_2:${hex32()}`);
  assert.deepEqual(Object.keys(keys), ['backend-1', 'backend_2']);
  assert.equal(keys['backend-1'].length, 32);

  const bad = [
    `x:${hex32()}`,                 // id too short
    'ok-id:abcd',                   // secret too short
    `ok-id:${'zz'.repeat(32)}`,     // not hex
    `__proto__:${hex32()}`,         // reserved id
    `constructor:${hex32()}`,
    hex32(),                        // no id at all
    `ok-id:${hex32()}0`,            // odd number of hex digits
  ];
  for (const spec of bad) {
    assert.throws(() => parseHmacKeys(spec), /OTP_HMAC_KEYS/, spec.slice(0, 20));
  }

  const config = loadConfig({ ...productionEnv(), OTP_API_KEY: undefined, OTP_HMAC_KEYS: `svc-1:${hex32()}` });
  assert.equal(config.apiKey, null);
  assert.ok(config.hmacKeys['svc-1']);
});

test('network and hardening options are validated, so typos fail at startup', () => {
  const config = loadConfig({
    ...productionEnv(),
    OTP_ALLOWED_CIDRS: '10.0.0.0/8, 127.0.0.1',
    OTP_TRUSTED_PROXIES: '::1',
    OTP_MIN_VERIFY_MS: '150',
    OTP_UNIFORM_ERRORS: 'strict',
    OTP_METRICS: '1',
  });
  assert.deepEqual(config.allowedCidrs, ['10.0.0.0/8', '127.0.0.1']);
  assert.equal(config.minVerifyMs, 150);
  assert.equal(config.uniformErrors, 'strict');
  assert.equal(config.metrics, true);

  assert.throws(() => loadConfig({ ...productionEnv(), OTP_ALLOWED_CIDRS: '10.0.0.0/99' }), /CIDR/);
  assert.throws(() => loadConfig({ ...productionEnv(), OTP_TRUSTED_PROXIES: 'banana' }), /CIDR/);
  assert.throws(() => loadConfig({ ...productionEnv(), OTP_MIN_VERIFY_MS: '999999' }), /MIN_VERIFY/);
  assert.throws(() => loadConfig({ ...productionEnv(), OTP_WEBAUTHN_RP_ID: 'example.com' }), /ORIGINS/);

  const webauthn = loadConfig({
    ...productionEnv(),
    OTP_WEBAUTHN_RP_ID: 'example.com',
    OTP_WEBAUTHN_ORIGINS: 'https://example.com',
  }).webauthn;
  assert.deepEqual([webauthn.rpId, webauthn.requireUV], ['example.com', true]);

  assert.equal(loadConfig({ ...productionEnv(), OTP_UNIFORM_ERRORS: 'off' }).uniformErrors, false);
});

test('production refuses a volatile store, and only one durable store can be chosen', () => {
  const env = productionEnv();
  delete env.OTP_STORE_FILE;

  assert.throws(() => loadConfig(env), /No durable store/);
  assert.equal(loadConfig({ ...env, OTP_ALLOW_MEMORY_STORE: '1' }).storeFile, null);
  assert.equal(loadConfig({ ...env, OTP_SQLITE_FILE: '/tmp/x.db' }).sqliteFile, '/tmp/x.db');
  assert.equal(
    loadConfig({ ...env, OTP_DATABASE_URL: 'postgres://u:p@h/db' }).databaseUrl,
    'postgres://u:p@h/db',
  );
  assert.throws(
    () => loadConfig({ ...env, OTP_DATABASE_URL: 'postgres://u:p@h/db', OTP_SQLITE_FILE: '/tmp/x.db' }),
    /only one/,
  );
  assert.equal(quiet(() => loadConfig({})).storeFile, null, 'dev mode may use memory');
});

test('WebAuthn attestation policy comes from the environment', { skip: !haveOpenssl && 'openssl missing' }, () => {
  const pki = makePki();
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'anchors-'));
  const anchorsFile = path.join(dir, 'roots.pem');
  fs.writeFileSync(anchorsFile, `${pki.rootPem}\n${pki.rootPem}`);

  const base = {
    ...productionEnv(),
    OTP_WEBAUTHN_RP_ID: 'example.com',
    OTP_WEBAUTHN_ORIGINS: 'https://example.com',
  };

  try {
    assert.deepEqual(loadConfig(base).webauthn.attestation.formats, ['none']);

    const config = loadConfig({
      ...base,
      OTP_WEBAUTHN_ATTESTATION_FORMATS: 'packed,fido-u2f',
      OTP_WEBAUTHN_TRUST_ANCHORS_FILE: anchorsFile,
      OTP_WEBAUTHN_AAGUID_ALLOWLIST: 'ee882879-721c-4913-9775-3dfcce97072a',
      OTP_WEBAUTHN_ALLOW_SELF: '0',
    });
    const policy = config.webauthn.attestation;
    assert.deepEqual(policy.formats, ['packed', 'fido-u2f']);
    assert.equal(policy.trustAnchors.length, 2);
    assert.equal(policy.allowSelfAttestation, false);

    assert.throws(() => loadConfig({ ...base, OTP_WEBAUTHN_ATTESTATION_FORMATS: 'tpm' }), /subset/);
    assert.throws(
      () => loadConfig({
        ...base,
        OTP_WEBAUTHN_ATTESTATION_FORMATS: 'packed',
        OTP_WEBAUTHN_REQUIRE_TRUSTED: '1',
      }),
      /trust anchor/,
    );
    assert.throws(
      () => loadConfig({
        ...base,
        OTP_WEBAUTHN_ATTESTATION_FORMATS: 'packed',
        OTP_WEBAUTHN_AAGUID_ALLOWLIST: 'ee882879-721c-4913-9775-3dfcce97072a',
      }),
      /trust anchor/,
    );
    assert.throws(() => loadConfig({ ...base, OTP_WEBAUTHN_AAGUID_DENYLIST: 'nope' }), /invalid AAGUID/);

    const emptyFile = path.join(dir, 'empty.pem');
    fs.writeFileSync(emptyFile, 'nothing here');
    assert.throws(
      () => loadConfig({ ...base, OTP_WEBAUTHN_TRUST_ANCHORS_FILE: emptyFile }),
      /no PEM certificates/,
    );
    assert.throws(
      () => loadConfig({ ...base, OTP_WEBAUTHN_TRUST_ANCHORS_FILE: path.join(dir, 'missing.pem') }),
      /ENOENT/,
    );
  } finally {
    pki.cleanup();
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('bin/server.js starts hardened from the environment and enforces it', async () => {
  const secret = randomBytes(32);
  const env = {
    ...process.env,
    NODE_ENV: 'production',
    PORT: '0',
    OTP_ALLOW_MEMORY_STORE: '1',
    OTP_MASTER_KEY: hex32(),
    OTP_PEPPER: hex32(),
    OTP_HMAC_KEYS: `ops-1:${secret.toString('hex')}`,
    OTP_ALLOWED_CIDRS: '127.0.0.0/8,::1',
    OTP_METRICS: '1',
    OTP_WEBAUTHN_RP_ID: 'example.com',
    OTP_WEBAUTHN_ORIGINS: 'https://example.com',
  };
  delete env.OTP_API_KEY;

  const server = startServer(env);
  try {
    const base = `http://127.0.0.1:${await server.ready}`;
    assert.match(server.output(), /auth: HMAC \(1 key id\(s\)\)/);
    assert.match(server.output(), /webauthn: on/);
    assert.ok(!/Dev API key/.test(server.output()));

    assert.equal((await fetch(`${base}/health`)).status, 200);
    assert.equal((await fetch(`${base}/metrics`)).status, 401);
    assert.equal((await fetch(`${base}/metrics`, { headers: { 'x-api-key': 'anything' } })).status, 401);

    const signature = signRequest({ method: 'GET', path: '/metrics', body: '', keyId: 'ops-1', secret });
    assert.equal((await fetch(`${base}/metrics`, { headers: signature })).status, 200);
    assert.equal((await fetch(`${base}/metrics`, { headers: signature })).status, 401, 'replayed signature');

    const route = '/webauthn/register/start';
    const body = JSON.stringify({ userId: 'u', userName: 'u' });
    const response = await fetch(base + route, {
      method: 'POST',
      headers: signRequest({ method: 'POST', path: route, body, keyId: 'ops-1', secret }),
      body,
    });
    assert.equal((await response.json()).options.rp.id, 'example.com');
  } finally {
    await server.stop();
  }
});

test('bin/server.js refuses to start with a bad config and says why', async () => {
  const { exitCode, stderr } = await expectStartupFailure({ ...process.env, NODE_ENV: 'production' });
  assert.notEqual(exitCode, 'server kept running');
  assert.notEqual(exitCode, 0);
  assert.match(stderr, /Missing required env var OTP_MASTER_KEY/);
});

// node:sqlite needs Node 22.5 or newer. Older versions use the JSON file store for this test.
let haveSqlite = true;
try {
  await import('../src/storage/sqlite-store.js');
} catch {
  haveSqlite = false;
}

test('data survives a restart with a durable store, and production refuses to run without one', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'persist-'));
  const dataFile = path.join(dir, haveSqlite ? 'otp.db' : 'otp.json');
  const storeEnv = haveSqlite ? { OTP_SQLITE_FILE: dataFile } : { OTP_STORE_FILE: dataFile };
  const apiKey = 'k'.repeat(24);

  const env = {
    ...process.env,
    NODE_ENV: 'production',
    PORT: '0',
    OTP_MASTER_KEY: hex32(),
    OTP_PEPPER: hex32(),
    OTP_API_KEY: apiKey,
    ...storeEnv,
  };

  const post = (port, route, body) => fetch(`http://127.0.0.1:${port}${route}`, {
    method: 'POST',
    headers: { 'x-api-key': apiKey },
    body: JSON.stringify(body),
  }).then((response) => response.json());

  try {
    const first = startServer(env);
    try {
      const port = await first.ready;
      assert.match(first.output(), haveSqlite ? /store: sqlite:/ : /store: file:/);
      await post(port, '/totp/enroll', { userId: 'persist-user', account: 'p@x.com' });
    } finally {
      await first.stop();
    }

    const second = startServer(env);
    try {
      const port = await second.ready;
      const known = await post(port, '/totp/confirm', { userId: 'persist-user', code: '000000' });
      assert.equal(known.reason, 'invalid_or_expired', 'the enrolment survived the restart');

      const unknown = await post(port, '/totp/confirm', { userId: 'someone-else', code: '000000' });
      assert.equal(unknown.reason, 'nothing_to_confirm');
    } finally {
      await second.stop();
    }
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }

  const withoutStore = { ...env };
  delete withoutStore.OTP_SQLITE_FILE;
  delete withoutStore.OTP_STORE_FILE;
  const { exitCode, stderr } = await expectStartupFailure(withoutStore);
  assert.notEqual(exitCode, 'server kept running', 'the server must refuse to start without a durable store');
  assert.notEqual(exitCode, 0);
  assert.match(stderr, /No durable store configured/);
});
