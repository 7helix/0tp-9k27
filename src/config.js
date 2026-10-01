import { randomBytes } from './core/crypto-utils.js';
import { parseCidr } from './http/cidr.js';

const list = (v) => (v ? String(v).split(',').map((s) => s.trim()).filter(Boolean) : []);
const RESERVED = new Set(['__proto__', 'constructor', 'prototype']);

/** Parse "id:hexsecret,id2:hexsecret" into { id: Buffer }. Secrets must be >= 32 bytes. */
export function parseHmacKeys(spec) {
  const keys = Object.create(null);
  for (const pair of list(spec)) {
    const i = pair.indexOf(':'); const id = pair.slice(0, i), hex = pair.slice(i + 1);
    if (i < 1 || !/^[A-Za-z0-9_-]{3,64}$/.test(id) || RESERVED.has(id)) throw new Error(`OTP_HMAC_KEYS: bad key id "${id}"`);
    if (!/^[0-9a-fA-F]{64,}$/.test(hex) || hex.length % 2) throw new Error(`OTP_HMAC_KEYS: secret for "${id}" must be >= 64 hex chars (32 bytes)`);
    keys[id] = Buffer.from(hex, 'hex');
  }
  return keys;
}

export function loadConfig(env = process.env) {
  const production = env.NODE_ENV === 'production';
  const need = (name) => {
    if (env[name]) return env[name];
    if (production) throw new Error(`Missing required env var ${name}`);
    console.warn(`[warn] ${name} not set - using an EPHEMERAL value (dev only)`);
    return null;
  };
  const keyHex = need('OTP_MASTER_KEY');
  const masterKey = keyHex ? Buffer.from(keyHex, 'hex') : randomBytes(32);
  if (masterKey.length !== 32) throw new Error('OTP_MASTER_KEY must be 64 hex chars (32 bytes)');
  const pepper = need('OTP_PEPPER') || randomBytes(32).toString('hex');
  if (pepper.length < 32 && production) throw new Error('OTP_PEPPER must be >= 32 chars');

  const hmacKeys = parseHmacKeys(env.OTP_HMAC_KEYS);
  const useHmac = Object.keys(hmacKeys).length > 0;
  const allowedCidrs = list(env.OTP_ALLOWED_CIDRS); allowedCidrs.forEach(parseCidr);       // fail fast on typos
  const trustedProxies = list(env.OTP_TRUSTED_PROXIES); trustedProxies.forEach(parseCidr);
  const minVerifyMs = Number(env.OTP_MIN_VERIFY_MS || 0);
  if (!Number.isFinite(minVerifyMs) || minVerifyMs < 0 || minVerifyMs > 5000) throw new Error('OTP_MIN_VERIFY_MS must be 0..5000');
  const origins = list(env.OTP_WEBAUTHN_ORIGINS);
  if (env.OTP_WEBAUTHN_RP_ID && !origins.length) throw new Error('OTP_WEBAUTHN_ORIGINS is required with OTP_WEBAUTHN_RP_ID');

  return {
    masterKey, pepper,
    apiKey: useHmac ? null : (need('OTP_API_KEY') || randomBytes(16).toString('hex')),
    hmacKeys: useHmac ? hmacKeys : null,
    allowedCidrs: allowedCidrs.length ? allowedCidrs : null,
    trustedProxies,
    minVerifyMs,
    uniformErrors: env.OTP_UNIFORM_ERRORS === 'strict' ? 'strict' : env.OTP_UNIFORM_ERRORS === 'off' ? false : true,
    metrics: env.OTP_METRICS === '1',
    webauthn: env.OTP_WEBAUTHN_RP_ID ? { rpId: env.OTP_WEBAUTHN_RP_ID, rpName: env.OTP_WEBAUTHN_RP_NAME || env.OTP_WEBAUTHN_RP_ID, origins, requireUV: env.OTP_WEBAUTHN_REQUIRE_UV !== '0' } : null,
    port: Number(env.PORT ?? 8080),
    auditFile: env.OTP_AUDIT_FILE || null,
    storeFile: env.OTP_STORE_FILE || null,
  };
}
