// Step-up authentication: after a successful OTP, mint a short-lived token that authorises ONE
// sensitive action (change email, withdraw funds ...) for ONE user. Optionally single-use.
import { sign, verify } from './signed-token.js';
import { randomBytes, b64url } from '../core/crypto-utils.js';

export class StepUp {
  constructor({ store, key, clock = Date.now }) { Object.assign(this, { store, key, clock }); }

  async grant({ userId, action, ttlMs = 300_000, singleUse = true }) {
    const jti = b64url(randomBytes(12));
    if (singleUse) await this.store.set(`stepup:${jti}`, { used: false }, ttlMs);
    return sign(this.key, { u: userId, a: action, jti, su: singleUse }, { ttlMs, now: this.clock() });
  }
  async check(token, { userId, action }) {
    const v = verify(this.key, token, { now: this.clock() });
    if (!v.ok) return { ok: false, reason: v.reason || 'invalid' };
    const p = v.payload;
    if (p.u !== userId) return { ok: false, reason: 'wrong_user' };
    if (p.a !== action) return { ok: false, reason: 'wrong_action' };
    if (p.su) {
      let won = false;
      await this.store.update(`stepup:${p.jti}`, (r) => { if (!r || r.used) return undefined; won = true; return { used: true }; });
      if (!won) return { ok: false, reason: 'already_used' };
    }
    return { ok: true };
  }
}
