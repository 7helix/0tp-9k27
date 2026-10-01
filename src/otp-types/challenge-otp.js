// Server-issued random OTP for email / SMS / voice channels.
// Design rules baked in:
//  * random (not derived) -> nothing to predict
//  * stored only as HMAC(pepper, salt|user|purpose|code) -> DB leak reveals nothing usable
//  * bound to user + purpose -> a login code cannot approve a password reset
//  * short TTL, single use, capped attempts (counted BEFORE comparing, atomically)
//  * issuing a new code invalidates the previous one
import { randomDigits, randomFromAlphabet, randomBytes, hmac, safeEqual, b64url } from '../core/crypto-utils.js';
import { normalizeNumericInput } from '../core/format.js';

// No 0/O, 1/I/L, U/V confusion - good for codes people type from a screen.
export const UNAMBIGUOUS = '23456789ABCDEFGHJKMNPQRSTWXYZ';

export class ChallengeOtp {
  constructor({ store, pepper, clock = Date.now }) {
    if (!pepper || pepper.length < 16) throw new Error('pepper must be at least 16 chars');
    Object.assign(this, { store, pepper, clock });
  }
  #key = (userId, purpose) => `otp:${purpose}:${userId}`;
  #hash(salt, userId, purpose, code) {
    return hmac('sha256', this.pepper, `${salt}|${userId}|${purpose}|${code}`).toString('hex');
  }
  // Accepts spaces/dashes and non-Latin digits (Devanagari, Telugu, Arabic-Indic, full-width ...).
  static normalize(code) { return normalizeNumericInput(String(code).normalize('NFKC')).toUpperCase(); }

  async issue({ userId, purpose, kind = 'numeric', length = 6, ttlMs = 300_000, maxAttempts = 5 }) {
    if (length < 6) throw new Error('length must be >= 6');
    const code = kind === 'numeric' ? randomDigits(length) : randomFromAlphabet(UNAMBIGUOUS, length);
    const salt = b64url(randomBytes(16));
    const expiresAt = this.clock() + ttlMs;
    await this.store.set(this.#key(userId, purpose), {
      salt, hash: this.#hash(salt, userId, purpose, code), attempts: 0, maxAttempts, expiresAt,
    }, ttlMs);
    return { code, expiresAt };
  }

  async verify({ userId, purpose, code }) {
    const key = this.#key(userId, purpose);
    // Count the attempt first and atomically, so parallel guesses cannot exceed the cap.
    const rec = await this.store.update(key, (r) => (r ? { ...r, attempts: r.attempts + 1 } : undefined));
    if (!rec) return { ok: false, reason: 'no_active_code' };
    if (rec.expiresAt <= this.clock()) { await this.store.del(key); return { ok: false, reason: 'expired' }; }
    if (rec.attempts > rec.maxAttempts) { await this.store.del(key); return { ok: false, reason: 'too_many_attempts' }; }
    const ok = safeEqual(this.#hash(rec.salt, userId, purpose, ChallengeOtp.normalize(code)), rec.hash);
    if (ok) { await this.store.del(key); return { ok: true }; }
    if (rec.attempts >= rec.maxAttempts) { await this.store.del(key); return { ok: false, reason: 'too_many_attempts' }; }
    return { ok: false, reason: 'invalid', attemptsLeft: rec.maxAttempts - rec.attempts };
  }
}
