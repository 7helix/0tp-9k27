// Account recovery with a waiting period, instead of "click this email link to skip 2FA".
// start -> the owner is told on every channel -> wait -> complete, unless the owner cancels.
// Someone who only has access to the email inbox can't get through the waiting period unnoticed.
import { randomBytes, b64url } from '../core/crypto-utils.js';
import { sign } from './signed-token.js';

const KEEP_AFTER_FINISH_MS = 7 * 86_400_000;

export class RecoveryRequest {
  constructor({ store, key, notify = async () => {}, delayMs = 72 * 3_600_000, clock = Date.now }) {
    this.store = store;
    this.key = key;
    this.notify = notify;
    this.delayMs = delayMs;
    this.clock = clock;
  }

  #key(requestId) {
    return `recov:${requestId}`;
  }

  async start({ userId }) {
    const requestId = b64url(randomBytes(16));
    const now = this.clock();
    const record = { userId, status: 'waiting', createdAt: now, eligibleAt: now + this.delayMs };

    // keep the record for a week after the wait so its final status can still be read
    await this.store.set(this.#key(requestId), record, this.delayMs + KEEP_AFTER_FINISH_MS);
    await this.notify(userId, { type: 'recovery_started', eligibleAt: record.eligibleAt, requestId });

    return { requestId, eligibleAt: record.eligibleAt };
  }

  // The real owner cancels, from any signed-in device or from the link in the notification.
  async cancel({ requestId, userId }) {
    let cancelled = false;
    await this.store.update(this.#key(requestId), (record) => {
      if (!record || record.userId !== userId || record.status !== 'waiting') return undefined;
      cancelled = true;
      return { ...record, status: 'cancelled' };
    });

    if (cancelled) await this.notify(userId, { type: 'recovery_cancelled', requestId });
    return { ok: cancelled };
  }

  async complete({ requestId }) {
    const now = this.clock();
    let outcome = { ok: false, reason: 'unknown' };

    await this.store.update(this.#key(requestId), (record) => {
      if (!record) return undefined;
      if (record.status !== 'waiting') {
        outcome = { ok: false, reason: record.status };
        return undefined;
      }
      if (now < record.eligibleAt) {
        outcome = { ok: false, reason: 'too_early', retryAfterMs: record.eligibleAt - now };
        return undefined;
      }
      outcome = { ok: true, userId: record.userId };
      return { ...record, status: 'completed' };
    });
    if (!outcome.ok) return outcome;

    await this.notify(outcome.userId, { type: 'recovery_completed', requestId });
    const token = sign(this.key, { u: outcome.userId, purpose: 'recovery' }, { ttlMs: 900_000, now });
    return { ok: true, userId: outcome.userId, token };
  }
}
