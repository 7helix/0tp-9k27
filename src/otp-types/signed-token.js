// Small HMAC-signed tokens with an expiry, for things like "this user just passed an OTP, let them
// continue". Deliberately not a JWT: the algorithm is fixed, so there is no `alg` header to attack.
import { hmac, b64url, fromB64url, safeEqual } from '../core/crypto-utils.js';

export function sign(key, payload, { ttlMs = 600_000, now = Date.now() } = {}) {
  const body = b64url(JSON.stringify({ ...payload, exp: now + ttlMs }));
  return `${body}.${b64url(hmac('sha256', key, body))}`;
}

export function verify(key, token, { now = Date.now() } = {}) {
  const [body, signature] = String(token).split('.');
  if (!body || !signature) return { ok: false };
  if (!safeEqual(b64url(hmac('sha256', key, body)), signature)) return { ok: false };

  const payload = JSON.parse(fromB64url(body).toString());
  if (payload.exp <= now) return { ok: false, reason: 'expired' };
  return { ok: true, payload };
}
