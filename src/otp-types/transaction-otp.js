// Transaction-bound OTP ("what you see is what you sign", like bank dynamic linking - PSD2).
// The code is an HMAC over the exact transaction details. If malware changes the payee or
// amount, the code the user received no longer matches and verification fails.
import { hkdf, hmac, randomBytes, b64url, safeEqual } from '../core/crypto-utils.js';
import { dynamicTruncate } from '../core/hotp.js';

const canonical = (t) => JSON.stringify([String(t.amount), String(t.currency), String(t.payee)]);

export class TransactionOtp {
  constructor({ store, masterKey, clock = Date.now }) { Object.assign(this, { store, masterKey, clock }); }
  #code(userId, tx, nonce) {
    const key = hkdf(this.masterKey, `txn-otp|${userId}`);
    return dynamicTruncate(hmac('sha256', key, `${nonce}|${canonical(tx)}`), 8);
  }
  async issue({ userId, tx, ttlMs = 180_000 }) {
    const nonce = b64url(randomBytes(16));
    await this.store.set(`txn:${userId}:${nonce}`, { attempts: 0, expiresAt: this.clock() + ttlMs }, ttlMs);
    return { nonce, code: this.#code(userId, tx, nonce), summary: `Pay ${tx.amount} ${tx.currency} to ${tx.payee}` };
  }
  async verify({ userId, tx, nonce, code }) {
    const key = `txn:${userId}:${nonce}`;
    const rec = await this.store.update(key, (r) => (r ? { ...r, attempts: r.attempts + 1 } : undefined));
    if (!rec || rec.expiresAt <= this.clock()) return { ok: false, reason: 'expired_or_unknown' };
    if (rec.attempts > 3) { await this.store.del(key); return { ok: false, reason: 'too_many_attempts' }; }
    if (!safeEqual(this.#code(userId, tx, nonce), String(code))) return { ok: false, reason: 'mismatch' };
    await this.store.del(key);
    return { ok: true };
  }
}
