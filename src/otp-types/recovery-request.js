// Delayed account recovery: safer than "click this email to bypass 2FA".
// start -> owner is notified on every channel -> waiting period -> complete (unless cancelled).
// An attacker who compromises only the email inbox is defeated by the cooling-off period.
import { randomBytes, b64url } from '../core/crypto-utils.js';
import { sign } from './signed-token.js';

export class RecoveryRequest {
  constructor({ store, key, notify = async () => {}, delayMs = 72 * 3_600_000, clock = Date.now }) { Object.assign(this, { store, key, notify, delayMs, clock }); }
  #k = (id) => `recov:${id}`;

  async start({ userId }) {
    const requestId = b64url(randomBytes(16)); const now = this.clock();
    const rec = { userId, status: 'waiting', createdAt: now, eligibleAt: now + this.delayMs };
    // Keep finished/cancelled records for a week so their final status stays readable.
    await this.store.set(this.#k(requestId), rec, this.delayMs + 7 * 86_400_000);
    await this.notify(userId, { type: 'recovery_started', eligibleAt: rec.eligibleAt, requestId });
    return { requestId, eligibleAt: rec.eligibleAt };
  }
  /** The real owner cancels from any signed-in device or via the link in the notification. */
  async cancel({ requestId, userId }) {
    let ok = false;
    await this.store.update(this.#k(requestId), (r) => {
      if (!r || r.userId !== userId || r.status !== 'waiting') return undefined;
      ok = true; return { ...r, status: 'cancelled' };
    });
    if (ok) await this.notify(userId, { type: 'recovery_cancelled', requestId });
    return { ok };
  }
  async complete({ requestId }) {
    let out = { ok: false, reason: 'unknown' };
    const now = this.clock();
    await this.store.update(this.#k(requestId), (r) => {
      if (!r) return undefined;
      if (r.status !== 'waiting') { out = { ok: false, reason: r.status }; return undefined; }
      if (now < r.eligibleAt) { out = { ok: false, reason: 'too_early', retryAfterMs: r.eligibleAt - now }; return undefined; }
      out = { ok: true, userId: r.userId };
      return { ...r, status: 'completed' };
    });
    if (!out.ok) return out;
    await this.notify(out.userId, { type: 'recovery_completed', requestId });
    return { ok: true, userId: out.userId, token: sign(this.key, { u: out.userId, purpose: 'recovery' }, { ttlMs: 900_000, now }) };
  }
}
