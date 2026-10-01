// TOTP - RFC 6238 (time-based one-time passwords)
import { hotp } from './hotp.js';
import { safeEqual } from './crypto-utils.js';

export function totpCounter(timeMs = Date.now(), step = 30, t0 = 0) {
  return Math.floor((Math.floor(timeMs / 1000) - t0) / step);
}

export function totp(secret, { time = Date.now(), step = 30, digits = 6, algorithm = 'SHA1', t0 = 0 } = {}) {
  return hotp(secret, totpCounter(time, step, t0), { digits, algorithm });
}

/**
 * Verify a TOTP code with clock-drift tolerance AND replay protection.
 * Pass `lastUsedCounter` (from your DB); on success persist the returned `counter`.
 */
export function verifyTotp(secret, code, opts = {}) {
  const { time = Date.now(), step = 30, digits = 6, algorithm = 'SHA1', t0 = 0, window = 1, lastUsedCounter = -1 } = opts;
  const current = totpCounter(time, step, t0);
  let match = null;
  let replay = false;
  // (`0 - window`, not `-window`: avoids a -0 delta when window is 0)
  for (let d = 0 - window; d <= window; d++) {
    const c = current + d;
    const ok = safeEqual(hotp(secret, c, { digits, algorithm }), String(code));
    if (ok && !match) {
      if (c <= lastUsedCounter) replay = true;
      else match = { counter: c, delta: d };
    }
  }
  if (match) return { valid: true, ...match };
  return { valid: false, reason: replay ? 'replayed' : 'invalid' };
}
