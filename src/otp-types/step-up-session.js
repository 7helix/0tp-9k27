// Step-up authentication. After a successful OTP, hand out a short-lived token that allows one
// sensitive action (change email, withdraw money, ...) for one user, once by default.
import { sign, verify } from './signed-token.js';
import { randomBytes, b64url } from '../core/crypto-utils.js';

export class StepUp {
  constructor({ store, key, clock = Date.now }) {
    this.store = store;
    this.key = key;
    this.clock = clock;
  }

  async grant({ userId, action, ttlMs = 300_000, singleUse = true }) {
    const jti = b64url(randomBytes(12));
    if (singleUse) await this.store.set(`stepup:${jti}`, { used: false }, ttlMs);

    return sign(this.key, { u: userId, a: action, jti, su: singleUse }, { ttlMs, now: this.clock() });
  }

  async check(token, { userId, action }) {
    const verified = verify(this.key, token, { now: this.clock() });
    if (!verified.ok) return { ok: false, reason: verified.reason || 'invalid' };

    const claims = verified.payload;
    if (claims.u !== userId) return { ok: false, reason: 'wrong_user' };
    if (claims.a !== action) return { ok: false, reason: 'wrong_action' };

    if (claims.su) {
      let firstUse = false;
      await this.store.update(`stepup:${claims.jti}`, (record) => {
        if (!record || record.used) return undefined;
        firstUse = true;
        return { used: true };
      });
      if (!firstUse) return { ok: false, reason: 'already_used' };
    }
    return { ok: true };
  }
}
