// Server side of WebAuthn (passkeys). Registration, login, challenge handling and credential storage.
// Attestation checking lives in attestation.js, key handling in keys.js.
import { decodeCbor, decodeFirst } from './cbor.js';
import { sha256, b64url, fromB64url, randomBytes, safeEqual } from '../core/crypto-utils.js';
import { SlidingWindowLimiter } from '../security/rate-limiter.js';
import { ALG, coseToJwk, verifySignature } from './keys.js';
import { verifyAttestation, normalizePolicy } from './attestation.js';

export { ALG, coseToJwk, verifySignature };

export const FLAGS = { UP: 0x01, UV: 0x04, BE: 0x08, BS: 0x10, AT: 0x40, ED: 0x80 };

// Browser responses are base64url strings. Nothing legitimate is anywhere near this big.
const MAX_FIELD = 16 * 1024;

const fail = (reason) => ({ ok: false, reason });

export function parseAuthData(buf) {
  if (buf.length < 37) throw new Error('authData too short');

  const result = {
    rpIdHash: buf.subarray(0, 32),
    flags: buf[32],
    signCount: buf.readUInt32BE(33),
    credential: null,
  };
  let pos = 37;

  if (result.flags & FLAGS.AT) {
    if (buf.length < pos + 18) throw new Error('attested credential data truncated');

    const aaguid = buf.subarray(pos, pos + 16);
    pos += 16;

    const idLength = buf.readUInt16BE(pos);
    pos += 2;
    if (idLength < 16 || idLength > 1023 || pos + idLength > buf.length) {
      throw new Error('bad credential id length');
    }
    const id = buf.subarray(pos, pos + idLength);
    pos += idLength;

    const decoded = decodeFirst(buf, pos);
    pos = decoded.offset;
    result.credential = { aaguid, id, cose: decoded.value };
  }

  // extensions: we don't use them, but we have to skip past them
  if (result.flags & FLAGS.ED) {
    pos = decodeFirst(buf, pos).offset;
  }

  if (pos !== buf.length) throw new Error('trailing bytes in authData');
  return result;
}

function checkClientData(raw, { type, expectedChallenge, origins }) {
  let clientData;
  try {
    clientData = JSON.parse(raw.toString('utf8'));
  } catch {
    return fail('bad_client_data');
  }

  if (clientData?.type !== type) return fail('wrong_type');
  if (typeof clientData.challenge !== 'string' || !safeEqual(clientData.challenge, expectedChallenge)) {
    return fail('challenge_mismatch');
  }
  if (!origins.includes(clientData.origin)) return fail('origin_mismatch');
  if (clientData.crossOrigin === true) return fail('cross_origin');
  return { ok: true };
}

function checkAuthData(authData, { rpId, requireUV }) {
  const expectedHash = sha256(rpId).toString('hex');
  if (!safeEqual(authData.rpIdHash.toString('hex'), expectedHash)) return fail('rp_id_mismatch');
  if (!(authData.flags & FLAGS.UP)) return fail('user_not_present');
  if (requireUV && !(authData.flags & FLAGS.UV)) return fail('user_not_verified');
  return { ok: true };
}

export function verifyRegistration({
  clientDataJSON,
  attestationObject,
  expectedChallenge,
  origins,
  rpId,
  requireUV = true,
  algs = Object.values(ALG),
  attestation = normalizePolicy(),
  now = Date.now(),
}) {
  const clientCheck = checkClientData(clientDataJSON, { type: 'webauthn.create', expectedChallenge, origins });
  if (!clientCheck.ok) return clientCheck;

  const attObj = decodeCbor(attestationObject);
  const rawAuthData = attObj instanceof Map ? attObj.get('authData') : null;
  if (!Buffer.isBuffer(rawAuthData)) return fail('bad_attestation');

  const authData = parseAuthData(rawAuthData);
  const authCheck = checkAuthData(authData, { rpId, requireUV });
  if (!authCheck.ok) return authCheck;
  if (!authData.credential) return fail('no_credential_data');

  const { alg, jwk } = coseToJwk(authData.credential.cose);
  if (!algs.includes(alg)) return fail('alg_not_allowed');

  const attested = verifyAttestation({
    fmt: attObj.get('fmt'),
    attStmt: attObj.get('attStmt'),
    authDataRaw: rawAuthData,
    authData,
    clientDataHash: sha256(clientDataJSON),
    credential: { alg, jwk },
    policy: attestation,
    now,
  });
  if (!attested.ok) return attested;

  return {
    ok: true,
    credential: {
      id: b64url(authData.credential.id),
      alg,
      jwk,
      signCount: authData.signCount,
      attestation: attested.info,
      backupEligible: !!(authData.flags & FLAGS.BE),
      backedUp: !!(authData.flags & FLAGS.BS),
      aaguid: authData.credential.aaguid.toString('hex'),
    },
  };
}

export function verifyAssertion({
  clientDataJSON,
  authenticatorData,
  signature,
  expectedChallenge,
  origins,
  rpId,
  credential,
  requireUV = true,
}) {
  const clientCheck = checkClientData(clientDataJSON, { type: 'webauthn.get', expectedChallenge, origins });
  if (!clientCheck.ok) return clientCheck;

  const authData = parseAuthData(authenticatorData);
  const authCheck = checkAuthData(authData, { rpId, requireUV });
  if (!authCheck.ok) return authCheck;

  const signedData = Buffer.concat([authenticatorData, sha256(clientDataJSON)]);
  const goodSignature = verifySignature({
    alg: credential.alg,
    jwk: credential.jwk,
    data: signedData,
    signature,
  });
  if (!goodSignature) return fail('bad_signature');

  // The counter has to go up. Synced passkeys always report 0, so only enforce it
  // when either side has ever seen a non-zero value.
  const counterInUse = credential.signCount > 0 || authData.signCount > 0;
  if (counterInUse && authData.signCount <= credential.signCount) return fail('sign_count_rollback');

  return {
    ok: true,
    signCount: authData.signCount,
    userVerified: !!(authData.flags & FLAGS.UV),
    backedUp: !!(authData.flags & FLAGS.BS),
  };
}

// Stateful wrapper: hands out challenges, consumes them, and keeps the credentials.
export class WebAuthn {
  constructor({
    store,
    rpId,
    rpName,
    origins,
    requireUV = true,
    algs = Object.values(ALG),
    attestation = {},
    challengeTtlMs = 300_000,
    clock = Date.now,
  }) {
    if (!rpId || !origins?.length) throw new Error('rpId and origins are required');

    this.store = store;
    this.rpId = rpId;
    this.rpName = rpName || rpId;
    this.origins = origins;
    this.requireUV = requireUV;
    this.algs = algs;
    this.challengeTtlMs = challengeTtlMs;
    this.clock = clock;

    // throws if the policy is nonsense, so a bad config fails at startup
    this.attestationPolicy = normalizePolicy(attestation);
    this.limiter = new SlidingWindowLimiter({ store, limit: 10, windowMs: 600_000, clock, name: 'webauthn' });
  }

  #credsKey(userId) {
    return `wa:creds:${userId}`;
  }

  async #newChallenge(userId, kind) {
    const challenge = b64url(randomBytes(32));
    const record = { challenge, expiresAt: this.clock() + this.challengeTtlMs };
    await this.store.set(`wa:chal:${kind}:${userId}`, record, this.challengeTtlMs);
    return challenge;
  }

  // Challenges are single use. Taking one deletes it in the same atomic step, so a replayed
  // response (or ten of them in parallel) only ever finds it once.
  async #takeChallenge(userId, kind) {
    let taken;
    await this.store.update(`wa:chal:${kind}:${userId}`, (record) => {
      taken = record;
      return record ? null : undefined;
    });
    if (taken && taken.expiresAt > this.clock()) return taken.challenge;
    return null;
  }

  async #credentials(userId) {
    return (await this.store.get(this.#credsKey(userId))) || [];
  }

  async listCredentials(userId) {
    const all = await this.#credentials(userId);
    return all.map((c) => ({
      id: c.id,
      createdAt: c.createdAt,
      lastUsedAt: c.lastUsedAt,
      backupEligible: c.backupEligible,
      backedUp: c.backedUp,
      alg: c.alg,
      attestation: c.attestation,
    }));
  }

  async removeCredential({ userId, credentialId }) {
    let removed = false;
    await this.store.update(this.#credsKey(userId), (list) => {
      if (!list?.some((c) => c.id === credentialId)) return undefined;
      removed = true;
      return list.filter((c) => c.id !== credentialId);
    });
    if (removed) await this.store.del(`wa:credid:${credentialId}`);
    return { ok: removed };
  }

  async startRegistration({ userId, userName, displayName }) {
    const limit = await this.limiter.hit(`reg:${userId}`);
    if (!limit.allowed) return { ok: false, reason: 'rate_limited', retryAfterMs: limit.retryAfterMs };

    // The user handle sent to the authenticator is random, never the email or database id.
    let handle = (await this.store.get(`wa:user:${userId}`))?.handle;
    if (!handle) {
      handle = b64url(randomBytes(32));
      await this.store.set(`wa:user:${userId}`, { handle });
    }

    const existing = await this.#credentials(userId);
    const formats = this.attestationPolicy.formats;
    const wantsAttestation = !(formats.length === 1 && formats[0] === 'none');

    return {
      ok: true,
      options: {
        rp: { id: this.rpId, name: this.rpName },
        user: { id: handle, name: userName, displayName: displayName || userName },
        challenge: await this.#newChallenge(userId, 'reg'),
        pubKeyCredParams: this.algs.map((alg) => ({ type: 'public-key', alg })),
        timeout: 60_000,
        attestation: wantsAttestation ? 'direct' : 'none',
        authenticatorSelection: {
          residentKey: 'preferred',
          userVerification: this.requireUV ? 'required' : 'preferred',
        },
        excludeCredentials: existing.map((c) => ({ type: 'public-key', id: c.id })),
      },
    };
  }

  async finishRegistration({ userId, response }) {
    const challenge = await this.#takeChallenge(userId, 'reg');
    if (!challenge) return fail('no_active_challenge');

    try {
      const fields = this.#decodeFields(response, ['id', 'clientDataJSON', 'attestationObject']);
      const result = verifyRegistration({
        clientDataJSON: fields.clientDataJSON,
        attestationObject: fields.attestationObject,
        expectedChallenge: challenge,
        origins: this.origins,
        rpId: this.rpId,
        requireUV: this.requireUV,
        algs: this.algs,
        attestation: this.attestationPolicy,
        now: this.clock(),
      });
      if (!result.ok) return result;

      const credential = result.credential;
      if (response.id !== credential.id) return fail('id_mismatch');

      // One authenticator credential can only belong to one account.
      let claimed = false;
      await this.store.update(`wa:credid:${credential.id}`, (existing) => {
        if (existing) return undefined;
        claimed = true;
        return { userId };
      });
      if (!claimed) return fail('credential_exists');

      await this.store.update(this.#credsKey(userId), (list) => [
        ...(list || []),
        { ...credential, createdAt: this.clock(), lastUsedAt: null },
      ]);

      return {
        ok: true,
        credentialId: credential.id,
        backupEligible: credential.backupEligible,
        attestation: credential.attestation,
      };
    } catch {
      return fail('malformed');
    }
  }

  async startAuthentication({ userId }) {
    const limit = await this.limiter.hit(`auth:${userId}`);
    if (!limit.allowed) return { ok: false, reason: 'rate_limited', retryAfterMs: limit.retryAfterMs };

    const credentials = await this.#credentials(userId);
    if (credentials.length === 0) return fail('no_credentials');

    return {
      ok: true,
      options: {
        challenge: await this.#newChallenge(userId, 'auth'),
        rpId: this.rpId,
        timeout: 60_000,
        userVerification: this.requireUV ? 'required' : 'preferred',
        allowCredentials: credentials.map((c) => ({ type: 'public-key', id: c.id })),
      },
    };
  }

  async finishAuthentication({ userId, response }) {
    const challenge = await this.#takeChallenge(userId, 'auth');
    if (!challenge) return fail('no_active_challenge');

    try {
      const fields = this.#decodeFields(response, ['id', 'clientDataJSON', 'authenticatorData', 'signature']);

      const credentials = await this.#credentials(userId);
      const credential = credentials.find((c) => c.id === response.id);
      if (!credential) return fail('unknown_credential');

      const result = verifyAssertion({
        clientDataJSON: fields.clientDataJSON,
        authenticatorData: fields.authenticatorData,
        signature: fields.signature,
        expectedChallenge: challenge,
        origins: this.origins,
        rpId: this.rpId,
        credential,
        requireUV: this.requireUV,
      });
      if (!result.ok) return result;

      await this.store.update(this.#credsKey(userId), (list) => list.map((c) => {
        if (c.id !== credential.id) return c;
        return { ...c, signCount: result.signCount, lastUsedAt: this.clock(), backedUp: result.backedUp };
      }));

      return { ok: true, userId, credentialId: credential.id, userVerified: result.userVerified };
    } catch {
      return fail('malformed');
    }
  }

  // Turns the base64url strings from the browser into buffers. The id stays a string.
  #decodeFields(response, names) {
    const decoded = {};
    for (const name of names) {
      const value = response?.[name];
      if (typeof value !== 'string' || value.length > MAX_FIELD) throw new Error(`bad ${name}`);
      if (name !== 'id') decoded[name] = fromB64url(value);
    }
    return decoded;
  }
}
