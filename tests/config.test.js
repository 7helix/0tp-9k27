import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { loadConfig, parseHmacKeys, randomBytes, signRequest } from '../src/index.js';

const quiet = (fn) => { const w = console.warn; console.warn = () => {}; try { return fn(); } finally { console.warn = w; } };
const prodEnv = () => ({ NODE_ENV: 'production', OTP_MASTER_KEY: randomBytes(32).toString('hex'), OTP_PEPPER: randomBytes(32).toString('hex'), OTP_API_KEY: 'k'.repeat(20) });
const hex32 = () => randomBytes(32).toString('hex');

test('config: dev mode fills ephemeral secrets; production refuses to start without them', () => {
  const dev = quiet(() => loadConfig({}));
  assert.equal(dev.masterKey.length, 32); assert.ok(dev.apiKey && dev.port === 8080 && dev.uniformErrors === true);
  for (const missing of ['OTP_MASTER_KEY', 'OTP_PEPPER', 'OTP_API_KEY']) { const e = prodEnv(); delete e[missing]; assert.throws(() => loadConfig(e), new RegExp(missing)); }
  assert.throws(() => loadConfig({ ...prodEnv(), OTP_PEPPER: 'short' }), /PEPPER/);
  assert.throws(() => quiet(() => loadConfig({ OTP_MASTER_KEY: 'abcd' })), /64 hex/);
});
test('config: hmac keys parsed, validated, reserved ids and weak secrets rejected', () => {
  const k = parseHmacKeys(`backend-1:${hex32()}, backend_2:${hex32()}`);
  assert.deepEqual(Object.keys(k), ['backend-1', 'backend_2']); assert.equal(k['backend-1'].length, 32);
  for (const bad of ['x:' + hex32(), 'ok-id:abcd', `ok-id:${'zz'.repeat(32)}`, `__proto__:${hex32()}`, `constructor:${hex32()}`, hex32(), `ok-id:${hex32()}0`]) assert.throws(() => parseHmacKeys(bad), /OTP_HMAC_KEYS/, bad.slice(0, 20));
  const c = loadConfig({ ...prodEnv(), OTP_API_KEY: undefined, OTP_HMAC_KEYS: `svc-1:${hex32()}` });
  assert.equal(c.apiKey, null); assert.ok(c.hmacKeys['svc-1']);
});
test('config: network/hardening options validated (fail fast on typos)', () => {
  const c = loadConfig({ ...prodEnv(), OTP_ALLOWED_CIDRS: '10.0.0.0/8, 127.0.0.1', OTP_TRUSTED_PROXIES: '::1', OTP_MIN_VERIFY_MS: '150', OTP_UNIFORM_ERRORS: 'strict', OTP_METRICS: '1' });
  assert.deepEqual(c.allowedCidrs, ['10.0.0.0/8', '127.0.0.1']); assert.equal(c.minVerifyMs, 150); assert.equal(c.uniformErrors, 'strict'); assert.equal(c.metrics, true);
  assert.throws(() => loadConfig({ ...prodEnv(), OTP_ALLOWED_CIDRS: '10.0.0.0/99' }), /CIDR/);
  assert.throws(() => loadConfig({ ...prodEnv(), OTP_TRUSTED_PROXIES: 'banana' }), /CIDR/);
  assert.throws(() => loadConfig({ ...prodEnv(), OTP_MIN_VERIFY_MS: '999999' }), /MIN_VERIFY/);
  assert.throws(() => loadConfig({ ...prodEnv(), OTP_WEBAUTHN_RP_ID: 'example.com' }), /ORIGINS/);
  const w = loadConfig({ ...prodEnv(), OTP_WEBAUTHN_RP_ID: 'example.com', OTP_WEBAUTHN_ORIGINS: 'https://example.com' });
  assert.deepEqual([w.webauthn.rpId, w.webauthn.requireUV], ['example.com', true]);
  assert.equal(loadConfig({ ...prodEnv(), OTP_UNIFORM_ERRORS: 'off' }).uniformErrors, false);
});

test('bin/server.js boots fully hardened from env and enforces it (HMAC + metrics + webauthn + allowlist)', async () => {
  const secret = randomBytes(32);
  const env = { ...process.env, NODE_ENV: 'production', PORT: '0', OTP_MASTER_KEY: hex32(), OTP_PEPPER: hex32(), OTP_HMAC_KEYS: `ops-1:${secret.toString('hex')}`, OTP_ALLOWED_CIDRS: '127.0.0.0/8,::1', OTP_METRICS: '1', OTP_WEBAUTHN_RP_ID: 'example.com', OTP_WEBAUTHN_ORIGINS: 'https://example.com' };
  delete env.OTP_API_KEY;
  const child = spawn(process.execPath, ['bin/server.js'], { env, stdio: ['ignore', 'pipe', 'pipe'] });
  let out = ''; let errOut = ''; child.stderr.on('data', (d) => (errOut += d)); child.stdout.on('data', (d) => (out += d));
  try {
    const port = await new Promise((resolve, reject) => {
      const t = setTimeout(() => reject(new Error(`server did not start: ${out} ${errOut}`)), 8000);
      // wait for BOTH startup lines (they can arrive in separate chunks)
      child.stdout.on('data', () => { const m = /listening on :(\d+)[\s\S]*auth: .*\n/.exec(out); if (m) { clearTimeout(t); resolve(Number(m[1])); } });
      child.on('exit', (c) => reject(new Error(`server exited ${c}: ${errOut}`)));
    });
    const base = `http://127.0.0.1:${port}`;
    assert.match(out, /auth: HMAC \(1 key id\(s\)\)/); assert.match(out, /webauthn: on/); assert.ok(!/Dev API key/.test(out));
    assert.equal((await fetch(`${base}/health`)).status, 200);
    assert.equal((await fetch(`${base}/metrics`)).status, 401);
    assert.equal((await fetch(`${base}/metrics`, { headers: { 'x-api-key': 'anything' } })).status, 401);
    const sig = signRequest({ method: 'GET', path: '/metrics', body: '', keyId: 'ops-1', secret });
    assert.equal((await fetch(`${base}/metrics`, { headers: sig })).status, 200);
    assert.equal((await fetch(`${base}/metrics`, { headers: sig })).status, 401, 'replayed signature rejected');
    const body = JSON.stringify({ userId: 'u', userName: 'u' });
    const reg = await fetch(`${base}/webauthn/register/start`, { method: 'POST', headers: signRequest({ method: 'POST', path: '/webauthn/register/start', body, keyId: 'ops-1', secret }), body });
    assert.equal((await reg.json()).options.rp.id, 'example.com');
  } finally { child.kill('SIGTERM'); await new Promise((r) => child.on('exit', r)); }
});
test('bin/server.js refuses to start with a bad config (and says why)', async () => {
  const child = spawn(process.execPath, ['bin/server.js'], { env: { ...process.env, NODE_ENV: 'production' }, stdio: ['ignore', 'pipe', 'pipe'] });
  let err = ''; child.stderr.on('data', (d) => (err += d));
  const code = await new Promise((r) => child.on('exit', r));
  assert.notEqual(code, 0); assert.match(err, /Missing required env var OTP_MASTER_KEY/);
});
