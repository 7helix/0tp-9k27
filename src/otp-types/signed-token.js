// Compact HMAC-signed, expiring tokens (for "continue after OTP" step-up sessions,
// account-recovery links, etc.). Intentionally not JWT: fixed algorithm, no `alg` header attacks.
import { hmac, b64url, fromB64url, safeEqual } from '../core/crypto-utils.js';

export function sign(key, payload, { ttlMs = 600_000, now = Date.now() } = {}) {
  const body = b64url(JSON.stringify({ ...payload, exp: now + ttlMs }));
  return `${body}.${b64url(hmac('sha256', key, body))}`;
}
export function verify(key, token, { now = Date.now() } = {}) {
  const [body, sig] = String(token).split('.');
  if (!body || !sig || !safeEqual(b64url(hmac('sha256', key, body)), sig)) return { ok: false };
  const payload = JSON.parse(fromB64url(body).toString());
  return payload.exp > now ? { ok: true, payload } : { ok: false, reason: 'expired' };
}
