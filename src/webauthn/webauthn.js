// WebAuthn / passkeys (W3C Web Authentication Level 2/3 core), server side, zero dependencies.
// Supports: registration with attestation "none" (what passkey managers use), assertions,
// algorithms ES256 (-7), EdDSA (-8), RS256 (-257). Verifies challenge, origin, rpId hash, UP/UV flags,
// signature, and the signature counter (cloned-authenticator detection).
//
// Why it matters: the signature covers the ORIGIN the browser saw, so a phishing site on another
// domain cannot obtain a usable assertion - unlike every OTP in this repo.
import crypto from 'node:crypto';
import { decodeCbor, decodeFirst } from './cbor.js';
import { sha256, b64url, fromB64url, randomBytes, safeEqual } from '../core/crypto-utils.js';
import { SlidingWindowLimiter } from '../security/rate-limiter.js';

export const FLAGS = { UP: 0x01, UV: 0x04, BE: 0x08, BS: 0x10, AT: 0x40, ED: 0x80 };
export const ALG = { ES256: -7, EdDSA: -8, RS256: -257 };
const MAX_FIELD = 16 * 1024;

export function parseAuthData(buf) {
  if (buf.length < 37) throw new Error('authData too short');
  const out = { rpIdHash: buf.subarray(0, 32), flags: buf[32], signCount: buf.readUInt32BE(33), credential: null };
  let off = 37;
  if (out.flags & FLAGS.AT) {
    if (buf.length < off + 18) throw new Error('attested credential data truncated');
    const aaguid = buf.subarray(off, off + 16); off += 16;
    const idLen = buf.readUInt16BE(off); off += 2;
    if (idLen < 16 || idLen > 1023 || off + idLen > buf.length) throw new Error('bad credential id length');
    const id = buf.subarray(off, off + idLen); off += idLen;
    const { value: cose, offset } = decodeFirst(buf, off); off = offset;
    out.credential = { aaguid, id, cose };
  }
  if (out.flags & FLAGS.ED) { off = decodeFirst(buf, off).offset; }
  if (off !== buf.length) throw new Error('trailing bytes in authData');
  return out;
}

export function coseToJwk(cose) {
  if (!(cose instanceof Map)) throw new Error('COSE key must be a map');
  const kty = cose.get(1), alg = cose.get(3);
  const bytes = (k, n) => { const v = cose.get(k); if (!Buffer.isBuffer(v) || (n && v.length !== n)) throw new Error('bad COSE parameter'); return v; };
  if (alg === ALG.ES256 && kty === 2 && cose.get(-1) === 1) return { alg, jwk: { kty: 'EC', crv: 'P-256', x: b64url(bytes(-2, 32)), y: b64url(bytes(-3, 32)) } };
  if (alg === ALG.EdDSA && kty === 1 && cose.get(-1) === 6) return { alg, jwk: { kty: 'OKP', crv: 'Ed25519', x: b64url(bytes(-2, 32)) } };
  if (alg === ALG.RS256 && kty === 3) {
    const n = bytes(-1); if (n.length < 256) throw new Error('RSA key below 2048 bits');
    return { alg, jwk: { kty: 'RSA', n: b64url(n), e: b64url(bytes(-2)) } };
  }
  throw new Error('unsupported COSE key');
}

export function verifySignature({ alg, jwk, data, signature }) {
  try {
    const key = crypto.createPublicKey({ key: jwk, format: 'jwk' });   // also rejects off-curve EC points
    if (alg === ALG.EdDSA) return crypto.verify(null, data, key, signature);
    if (alg === ALG.ES256 || alg === ALG.RS256) return crypto.verify('sha256', data, key, signature);
  } catch { /* fall through */ }
  return false;
}

function checkClientData(raw, { type, expectedChallenge, origins }) {
  let cd;
  try { cd = JSON.parse(raw.toString('utf8')); } catch { return { ok: false, reason: 'bad_client_data' }; }
  if (cd?.type !== type) return { ok: false, reason: 'wrong_type' };
  if (typeof cd.challenge !== 'string' || !safeEqual(cd.challenge, expectedChallenge)) return { ok: false, reason: 'challenge_mismatch' };
  if (!origins.includes(cd.origin)) return { ok: false, reason: 'origin_mismatch' };
  if (cd.crossOrigin === true) return { ok: false, reason: 'cross_origin' };
  return { ok: true };
}
function checkAuthData(ad, { rpId, requireUV }) {
  if (!safeEqual(ad.rpIdHash.toString('hex'), sha256(rpId).toString('hex'))) return { ok: false, reason: 'rp_id_mismatch' };
  if (!(ad.flags & FLAGS.UP)) return { ok: false, reason: 'user_not_present' };
  if (requireUV && !(ad.flags & FLAGS.UV)) return { ok: false, reason: 'user_not_verified' };
  return { ok: true };
}

export function verifyRegistration({ clientDataJSON, attestationObject, expectedChallenge, origins, rpId, requireUV = true, algs = Object.values(ALG) }) {
  const cdv = checkClientData(clientDataJSON, { type: 'webauthn.create', expectedChallenge, origins });
  if (!cdv.ok) return cdv;
  const att = decodeCbor(attestationObject);
  if (!(att instanceof Map) || !Buffer.isBuffer(att.get('authData'))) return { ok: false, reason: 'bad_attestation' };
  if (att.get('fmt') !== 'none' || !(att.get('attStmt') instanceof Map) || att.get('attStmt').size !== 0) return { ok: false, reason: 'unsupported_attestation' };
  const ad = parseAuthData(att.get('authData'));
  const chk = checkAuthData(ad, { rpId, requireUV });
  if (!chk.ok) return chk;
  if (!ad.credential) return { ok: false, reason: 'no_credential_data' };
  const { alg, jwk } = coseToJwk(ad.credential.cose);
  if (!algs.includes(alg)) return { ok: false, reason: 'alg_not_allowed' };
  return { ok: true, credential: {
    id: b64url(ad.credential.id), alg, jwk, signCount: ad.signCount,
    backupEligible: !!(ad.flags & FLAGS.BE), backedUp: !!(ad.flags & FLAGS.BS), aaguid: ad.credential.aaguid.toString('hex'),
  } };
}

export function verifyAssertion({ clientDataJSON, authenticatorData, signature, expectedChallenge, origins, rpId, credential, requireUV = true }) {
  const cdv = checkClientData(clientDataJSON, { type: 'webauthn.get', expectedChallenge, origins });
  if (!cdv.ok) return cdv;
  const ad = parseAuthData(authenticatorData);
  const chk = checkAuthData(ad, { rpId, requireUV });
  if (!chk.ok) return chk;
  const data = Buffer.concat([authenticatorData, sha256(clientDataJSON)]);
  if (!verifySignature({ alg: credential.alg, jwk: credential.jwk, data, signature })) return { ok: false, reason: 'bad_signature' };
  // Counter must increase, unless the authenticator doesn't implement one (always 0; typical for synced passkeys).
  if ((credential.signCount > 0 || ad.signCount > 0) && ad.signCount <= credential.signCount) return { ok: false, reason: 'sign_count_rollback' };
  return { ok: true, signCount: ad.signCount, userVerified: !!(ad.flags & FLAGS.UV), backedUp: !!(ad.flags & FLAGS.BS) };
}

/** Stateful service: challenge issuing/consumption + credential storage on top of the pure verifiers. */
export class WebAuthn {
  constructor({ store, rpId, rpName, origins, requireUV = true, algs = Object.values(ALG), challengeTtlMs = 300_000, clock = Date.now }) {
    if (!rpId || !origins?.length) throw new Error('rpId and origins are required');
    Object.assign(this, { store, rpId, rpName: rpName || rpId, origins, requireUV, algs, challengeTtlMs, clock });
    this.limiter = new SlidingWindowLimiter({ store, limit: 10, windowMs: 600_000, clock, name: 'webauthn' });
  }
  #creds = (u) => `wa:creds:${u}`;
  async #newChallenge(userId, kind) {
    const challenge = b64url(randomBytes(32));
    await this.store.set(`wa:chal:${kind}:${userId}`, { challenge, expiresAt: this.clock() + this.challengeTtlMs }, this.challengeTtlMs);
    return challenge;
  }
  /** Single use: atomically removed the first time anyone tries it (kills replays & parallel races). */
  async #take(userId, kind) {
    let taken;
    await this.store.update(`wa:chal:${kind}:${userId}`, (r) => { taken = r; return r ? null : undefined; });
    return taken && taken.expiresAt > this.clock() ? taken.challenge : null;
  }
  async listCredentials(userId) {
    return ((await this.store.get(this.#creds(userId))) || []).map(({ id, createdAt, lastUsedAt, backupEligible, backedUp, alg }) => ({ id, createdAt, lastUsedAt, backupEligible, backedUp, alg }));
  }
  async removeCredential({ userId, credentialId }) {
    let removed = false;
    await this.store.update(this.#creds(userId), (l) => { if (!l?.some((c) => c.id === credentialId)) return undefined; removed = true; return l.filter((c) => c.id !== credentialId); });
    if (removed) await this.store.del(`wa:credid:${credentialId}`);
    return { ok: removed };
  }

  async startRegistration({ userId, userName, displayName }) {
    const rl = await this.limiter.hit(`reg:${userId}`);
    if (!rl.allowed) return { ok: false, reason: 'rate_limited', retryAfterMs: rl.retryAfterMs };
    let handle = (await this.store.get(`wa:user:${userId}`))?.handle;
    if (!handle) { handle = b64url(randomBytes(32)); await this.store.set(`wa:user:${userId}`, { handle }); }
    const existing = (await this.store.get(this.#creds(userId))) || [];
    return { ok: true, options: {
      rp: { id: this.rpId, name: this.rpName },
      user: { id: handle, name: userName, displayName: displayName || userName },   // opaque random handle, never the email
      challenge: await this.#newChallenge(userId, 'reg'),
      pubKeyCredParams: this.algs.map((alg) => ({ type: 'public-key', alg })),
      timeout: 60_000, attestation: 'none',
      authenticatorSelection: { residentKey: 'preferred', userVerification: this.requireUV ? 'required' : 'preferred' },
      excludeCredentials: existing.map((c) => ({ type: 'public-key', id: c.id })),
    } };
  }
  async finishRegistration({ userId, response }) {
    const challenge = await this.#take(userId, 'reg');
    if (!challenge) return { ok: false, reason: 'no_active_challenge' };
    try {
      const f = this.#fields(response, ['id', 'clientDataJSON', 'attestationObject']);
      const r = verifyRegistration({ clientDataJSON: f.clientDataJSON, attestationObject: f.attestationObject, expectedChallenge: challenge, origins: this.origins, rpId: this.rpId, requireUV: this.requireUV, algs: this.algs });
      if (!r.ok) return r;
      if (response.id !== r.credential.id) return { ok: false, reason: 'id_mismatch' };
      let claimed = false;
      await this.store.update(`wa:credid:${r.credential.id}`, (c) => { if (c) return undefined; claimed = true; return { userId }; });
      if (!claimed) return { ok: false, reason: 'credential_exists' };
      await this.store.update(this.#creds(userId), (l) => [...(l || []), { ...r.credential, createdAt: this.clock(), lastUsedAt: null }]);
      return { ok: true, credentialId: r.credential.id, backupEligible: r.credential.backupEligible };
    } catch { return { ok: false, reason: 'malformed' }; }
  }

  async startAuthentication({ userId }) {
    const rl = await this.limiter.hit(`auth:${userId}`);
    if (!rl.allowed) return { ok: false, reason: 'rate_limited', retryAfterMs: rl.retryAfterMs };
    const creds = (await this.store.get(this.#creds(userId))) || [];
    if (!creds.length) return { ok: false, reason: 'no_credentials' };
    return { ok: true, options: {
      challenge: await this.#newChallenge(userId, 'auth'), rpId: this.rpId, timeout: 60_000,
      userVerification: this.requireUV ? 'required' : 'preferred',
      allowCredentials: creds.map((c) => ({ type: 'public-key', id: c.id })),
    } };
  }
  async finishAuthentication({ userId, response }) {
    const challenge = await this.#take(userId, 'auth');
    if (!challenge) return { ok: false, reason: 'no_active_challenge' };
    try {
      const f = this.#fields(response, ['id', 'clientDataJSON', 'authenticatorData', 'signature']);
      const cred = ((await this.store.get(this.#creds(userId))) || []).find((c) => c.id === response.id);
      if (!cred) return { ok: false, reason: 'unknown_credential' };
      const r = verifyAssertion({ clientDataJSON: f.clientDataJSON, authenticatorData: f.authenticatorData, signature: f.signature, expectedChallenge: challenge, origins: this.origins, rpId: this.rpId, credential: cred, requireUV: this.requireUV });
      if (!r.ok) return r;
      await this.store.update(this.#creds(userId), (l) => l.map((c) => (c.id === cred.id ? { ...c, signCount: r.signCount, lastUsedAt: this.clock(), backedUp: r.backedUp } : c)));
      return { ok: true, userId, credentialId: cred.id, userVerified: r.userVerified };
    } catch { return { ok: false, reason: 'malformed' }; }
  }
  #fields(resp, names) {
    const out = {};
    for (const n of names) {
      if (typeof resp?.[n] !== 'string' || resp[n].length > MAX_FIELD) throw new Error(`bad ${n}`);
      if (n !== 'id') out[n] = fromB64url(resp[n]);
    }
    return out;
  }
}
