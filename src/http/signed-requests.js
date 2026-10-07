// HMAC request signing, in the spirit of AWS SigV4. Compared to a static API key the secret never
// goes over the wire, the body is covered by the signature, and every request can only be used once.
import { hmac, sha256hex, safeEqual, randomBytes, b64url } from '../core/crypto-utils.js';

const HEADERS = {
  keyId: 'x-otpf-key-id',
  timestamp: 'x-otpf-timestamp',
  nonce: 'x-otpf-nonce',
  signature: 'x-otpf-signature',
};

// What actually gets signed: method, path, timestamp, nonce and a hash of the body, one per line.
function canonicalString({ method, path, timestamp, nonce, body }) {
  return [method.toUpperCase(), path, timestamp, nonce, sha256hex(body)].join('\n');
}

function sign(secret, parts) {
  return hmac('sha256', secret, canonicalString(parts)).toString('base64url');
}

export function signRequest({ method, path, body = '', keyId, secret, now = Date.now(), nonce = b64url(randomBytes(16)) }) {
  const timestamp = String(now);
  return {
    [HEADERS.keyId]: keyId,
    [HEADERS.timestamp]: timestamp,
    [HEADERS.nonce]: nonce,
    [HEADERS.signature]: sign(secret, { method, path, timestamp, nonce, body }),
  };
}

export async function verifyRequest({ method, path, body = '', headers, keys, store, now = Date.now(), skewMs = 60_000 }) {
  const keyId = headers[HEADERS.keyId];
  const timestamp = headers[HEADERS.timestamp];
  const nonce = headers[HEADERS.nonce];
  const signature = headers[HEADERS.signature];

  const wellFormed = keyId && timestamp && nonce && signature
    && /^[A-Za-z0-9_-]{8,64}$/.test(nonce)
    && /^\d{10,16}$/.test(timestamp);
  if (!wellFormed) return { ok: false, reason: 'missing_or_malformed' };

  // Do the HMAC even for an unknown key id, so the response time doesn't reveal which ids exist.
  const secret = Object.hasOwn(keys, keyId) ? keys[keyId] : null;
  const expected = sign(secret ?? 'dummy-secret-for-constant-time', { method, path, timestamp, nonce, body });
  const signatureMatches = safeEqual(expected, signature);

  if (!secret) return { ok: false, reason: 'unknown_key' };
  if (Math.abs(now - Number(timestamp)) > skewMs) return { ok: false, reason: 'stale' };
  if (!signatureMatches) return { ok: false, reason: 'bad_signature' };

  // Only claim the nonce once the signature is good, otherwise anyone could burn real nonces.
  let firstUse = false;
  await store.update(`nonce:${keyId}:${nonce}`, (existing) => {
    if (existing) return undefined;
    firstUse = true;
    return { seenAt: now };
  }, skewMs * 2);

  return firstUse ? { ok: true, keyId } : { ok: false, reason: 'replayed' };
}
