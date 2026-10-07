// Reads settings from environment variables and validates them up front, so a typo stops the
// server at startup instead of surfacing later. See .env.example for the full list.
import fs from 'node:fs';
import { randomBytes } from './core/crypto-utils.js';
import { parseCidr } from './http/cidr.js';
import { normalizePolicy } from './webauthn/attestation.js';

const RESERVED_KEY_IDS = new Set(['__proto__', 'constructor', 'prototype']);

function list(value) {
  if (!value) return [];
  return String(value).split(',').map((item) => item.trim()).filter(Boolean);
}

function splitPem(text) {
  return text.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g) || [];
}

// "backend-1:<64+ hex chars>,other:<hex>" becomes { 'backend-1': Buffer, other: Buffer }
export function parseHmacKeys(spec) {
  const keys = Object.create(null);

  for (const pair of list(spec)) {
    const colon = pair.indexOf(':');
    const id = pair.slice(0, colon);
    const hex = pair.slice(colon + 1);

    const idOk = colon >= 1 && /^[A-Za-z0-9_-]{3,64}$/.test(id) && !RESERVED_KEY_IDS.has(id);
    if (!idOk) throw new Error(`OTP_HMAC_KEYS: bad key id "${id}"`);

    const secretOk = /^[0-9a-fA-F]{64,}$/.test(hex) && hex.length % 2 === 0;
    if (!secretOk) throw new Error(`OTP_HMAC_KEYS: secret for "${id}" must be >= 64 hex chars (32 bytes)`);

    keys[id] = Buffer.from(hex, 'hex');
  }
  return keys;
}

function readAttestationPolicy(env) {
  const anchorsFile = env.OTP_WEBAUTHN_TRUST_ANCHORS_FILE;
  const trustAnchors = anchorsFile ? splitPem(fs.readFileSync(anchorsFile, 'utf8')) : [];
  if (anchorsFile && trustAnchors.length === 0) {
    throw new Error('OTP_WEBAUTHN_TRUST_ANCHORS_FILE contains no PEM certificates');
  }

  const formats = list(env.OTP_WEBAUTHN_ATTESTATION_FORMATS);
  const policy = {
    formats: formats.length ? formats : ['none'],
    trustAnchors,
    requireTrustedChain: env.OTP_WEBAUTHN_REQUIRE_TRUSTED === '1',
    allowSelfAttestation: env.OTP_WEBAUTHN_ALLOW_SELF !== '0',
    aaguidAllowlist: env.OTP_WEBAUTHN_AAGUID_ALLOWLIST ? list(env.OTP_WEBAUTHN_AAGUID_ALLOWLIST) : null,
    aaguidDenylist: list(env.OTP_WEBAUTHN_AAGUID_DENYLIST),
  };

  normalizePolicy(policy); // only to validate it now
  return policy;
}

function uniformErrorsMode(value) {
  if (value === 'strict') return 'strict';
  if (value === 'off') return false;
  return true;
}

export function loadConfig(env = process.env) {
  const production = env.NODE_ENV === 'production';

  // In production a missing secret is fatal. In dev we make up a throwaway one and say so.
  const need = (name) => {
    if (env[name]) return env[name];
    if (production) throw new Error(`Missing required env var ${name}`);
    console.warn(`[warn] ${name} not set - using an EPHEMERAL value (dev only)`);
    return null;
  };

  const masterKeyHex = need('OTP_MASTER_KEY');
  const masterKey = masterKeyHex ? Buffer.from(masterKeyHex, 'hex') : randomBytes(32);
  if (masterKey.length !== 32) throw new Error('OTP_MASTER_KEY must be 64 hex chars (32 bytes)');

  const pepper = need('OTP_PEPPER') || randomBytes(32).toString('hex');
  if (production && pepper.length < 32) throw new Error('OTP_PEPPER must be >= 32 chars');

  const hmacKeys = parseHmacKeys(env.OTP_HMAC_KEYS);
  const useHmac = Object.keys(hmacKeys).length > 0;

  const allowedCidrs = list(env.OTP_ALLOWED_CIDRS);
  const trustedProxies = list(env.OTP_TRUSTED_PROXIES);
  allowedCidrs.forEach(parseCidr); // throws on a typo
  trustedProxies.forEach(parseCidr);

  const minVerifyMs = Number(env.OTP_MIN_VERIFY_MS || 0);
  if (!Number.isFinite(minVerifyMs) || minVerifyMs < 0 || minVerifyMs > 5000) {
    throw new Error('OTP_MIN_VERIFY_MS must be 0..5000');
  }

  const origins = list(env.OTP_WEBAUTHN_ORIGINS);
  if (env.OTP_WEBAUTHN_RP_ID && origins.length === 0) {
    throw new Error('OTP_WEBAUTHN_ORIGINS is required with OTP_WEBAUTHN_RP_ID');
  }
  let webauthn = null;
  if (env.OTP_WEBAUTHN_RP_ID) {
    webauthn = {
      rpId: env.OTP_WEBAUTHN_RP_ID,
      rpName: env.OTP_WEBAUTHN_RP_NAME || env.OTP_WEBAUTHN_RP_ID,
      origins,
      requireUV: env.OTP_WEBAUTHN_REQUIRE_UV !== '0',
      attestation: readAttestationPolicy(env),
    };
  }

  // A volatile store in production would lose every enrolment, lockout and replay guard on restart.
  const databaseUrl = env.OTP_DATABASE_URL || null;
  const sqliteFile = env.OTP_SQLITE_FILE || null;
  const storeFile = env.OTP_STORE_FILE || null;
  const allowMemoryStore = env.OTP_ALLOW_MEMORY_STORE === '1';

  if (production && !databaseUrl && !sqliteFile && !storeFile && !allowMemoryStore) {
    throw new Error(
      'No durable store configured: set OTP_DATABASE_URL (Postgres), OTP_SQLITE_FILE or OTP_STORE_FILE '
      + '(or OTP_ALLOW_MEMORY_STORE=1 to accept data loss)',
    );
  }
  if (databaseUrl && sqliteFile) throw new Error('set only one of OTP_DATABASE_URL / OTP_SQLITE_FILE');

  return {
    masterKey,
    pepper,
    apiKey: useHmac ? null : (need('OTP_API_KEY') || randomBytes(16).toString('hex')),
    hmacKeys: useHmac ? hmacKeys : null,
    allowedCidrs: allowedCidrs.length ? allowedCidrs : null,
    trustedProxies,
    minVerifyMs,
    uniformErrors: uniformErrorsMode(env.OTP_UNIFORM_ERRORS),
    metrics: env.OTP_METRICS === '1',
    webauthn,
    port: Number(env.PORT ?? 8080),
    auditFile: env.OTP_AUDIT_FILE || null,
    storeFile,
    sqliteFile,
    databaseUrl,
  };
}
