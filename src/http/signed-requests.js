// HMAC request signing (like AWS SigV4 / Stripe-style): stronger than a static API key because
//  * the secret never travels on the wire,      * the body is covered (tampering breaks the signature),
//  * timestamps limit the replay window,        * one-time nonces stop replays inside that window,
//  * different key ids let you rotate/revoke callers independently.
import { hmac, sha256hex, safeEqual, randomBytes, b64url } from '../core/crypto-utils.js';

const canonical = ({ method, path, ts, nonce, bodyHash }) => [method.toUpperCase(), path, ts, nonce, bodyHash].join('\n');
const H = { key: 'x-otpf-key-id', ts: 'x-otpf-timestamp', nonce: 'x-otpf-nonce', sig: 'x-otpf-signature' };

export function signRequest({ method, path, body = '', keyId, secret, now = Date.now(), nonce = b64url(randomBytes(16)) }) {
  const ts = String(now);
  const sig = hmac('sha256', secret, canonical({ method, path, ts, nonce, bodyHash: sha256hex(body) })).toString('base64url');
  return { [H.key]: keyId, [H.ts]: ts, [H.nonce]: nonce, [H.sig]: sig };
}

export async function verifyRequest({ method, path, body = '', headers, keys, store, now = Date.now(), skewMs = 60_000 }) {
  const keyId = headers[H.key], ts = headers[H.ts], nonce = headers[H.nonce], sig = headers[H.sig];
  if (!keyId || !ts || !nonce || !sig || !/^[A-Za-z0-9_-]{8,64}$/.test(nonce) || !/^\d{10,16}$/.test(ts)) return { ok: false, reason: 'missing_or_malformed' };
  const secret = Object.hasOwn(keys, keyId) ? keys[keyId] : null;
  const expected = hmac('sha256', secret ?? 'dummy-secret-for-constant-time', canonical({ method, path, ts, nonce, bodyHash: sha256hex(body) })).toString('base64url');
  const sigOk = safeEqual(expected, sig);                       // always computed: unknown key costs the same
  if (!secret) return { ok: false, reason: 'unknown_key' };
  if (Math.abs(now - Number(ts)) > skewMs) return { ok: false, reason: 'stale' };
  if (!sigOk) return { ok: false, reason: 'bad_signature' };
  // Claim the nonce only AFTER the signature checks out, so forged requests can't burn legitimate nonces.
  let first = false;
  await store.update(`nonce:${keyId}:${nonce}`, (c) => { if (c) return undefined; first = true; return { t: now }; }, skewMs * 2);
  return first ? { ok: true, keyId } : { ok: false, reason: 'replayed' };
}
