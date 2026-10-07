// Random codes sent by email, SMS or voice call.
//
// The code is random, not derived from anything, so there is nothing to predict. Only an HMAC of it
// is stored (keyed with a server-side pepper), tied to the user and purpose, so a database leak
// doesn't hand out live codes and a login code can't approve a password reset. Codes expire, work
// once, allow a few attempts, and issuing a new one replaces the old one.
import { randomDigits, randomFromAlphabet, randomBytes, hmac, safeEqual, b64url } from '../core/crypto-utils.js';
import { normalizeNumericInput } from '../core/format.js';

// No 0/O, 1/I/L or U/V, so codes are easy to read off a screen
export const UNAMBIGUOUS = '23456789ABCDEFGHJKMNPQRSTWXYZ';

export class ChallengeOtp {
  constructor({ store, pepper, clock = Date.now }) {
    if (!pepper || pepper.length < 16) throw new Error('pepper must be at least 16 chars');
    this.store = store;
    this.pepper = pepper;
    this.clock = clock;
  }

  #key(userId, purpose) {
    return `otp:${purpose}:${userId}`;
  }

  #hash(salt, userId, purpose, code) {
    return hmac('sha256', this.pepper, `${salt}|${userId}|${purpose}|${code}`).toString('hex');
  }

  // Accepts spaces, dashes, lower case and digits from other scripts (Devanagari, Telugu, ...).
  static normalize(code) {
    return normalizeNumericInput(String(code).normalize('NFKC')).toUpperCase();
  }

  async issue({ userId, purpose, kind = 'numeric', length = 6, ttlMs = 300_000, maxAttempts = 5 }) {
    if (length < 6) throw new Error('length must be >= 6');

    const code = kind === 'numeric' ? randomDigits(length) : randomFromAlphabet(UNAMBIGUOUS, length);
    const salt = b64url(randomBytes(16));
    const expiresAt = this.clock() + ttlMs;

    await this.store.set(this.#key(userId, purpose), {
      salt,
      hash: this.#hash(salt, userId, purpose, code),
      attempts: 0,
      maxAttempts,
      expiresAt,
    }, ttlMs);

    return { code, expiresAt };
  }

  async verify({ userId, purpose, code }) {
    const key = this.#key(userId, purpose);

    // Count the attempt before comparing, in one atomic step. Otherwise a burst of parallel
    // guesses could all be checked before any of them is counted.
    const record = await this.store.update(key, (r) => (r ? { ...r, attempts: r.attempts + 1 } : undefined));
    if (!record) return { ok: false, reason: 'no_active_code' };

    if (record.expiresAt <= this.clock()) {
      await this.store.del(key);
      return { ok: false, reason: 'expired' };
    }
    if (record.attempts > record.maxAttempts) {
      await this.store.del(key);
      return { ok: false, reason: 'too_many_attempts' };
    }

    const hash = this.#hash(record.salt, userId, purpose, ChallengeOtp.normalize(code));
    if (safeEqual(hash, record.hash)) {
      await this.store.del(key);
      return { ok: true };
    }

    if (record.attempts >= record.maxAttempts) {
      await this.store.del(key);
      return { ok: false, reason: 'too_many_attempts' };
    }
    return { ok: false, reason: 'invalid', attemptsLeft: record.maxAttempts - record.attempts };
  }
}
