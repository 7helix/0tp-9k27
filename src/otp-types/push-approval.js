// Push approval with NUMBER MATCHING (defeats "MFA fatigue" / push-bombing).
// The login screen shows a number; the phone shows 3 numbers; the user must tap the right one.
// A wrong tap denies the request permanently.
import { randomBytes, b64url } from '../core/crypto-utils.js';
import crypto from 'node:crypto';

export class PushApproval {
  constructor({ store, clock = Date.now }) { Object.assign(this, { store, clock }); }

  async request({ userId, ttlMs = 120_000, context = {} }) {
    const requestId = b64url(randomBytes(16));
    const correct = crypto.randomInt(10, 100);
    const decoys = new Set();
    while (decoys.size < 2) { const d = crypto.randomInt(10, 100); if (d !== correct) decoys.add(d); }
    const choices = [correct, ...decoys].sort(() => crypto.randomInt(0, 2) - 0.5);
    await this.store.set(`push:${requestId}`, { userId, correct, status: 'pending', expiresAt: this.clock() + ttlMs, context }, ttlMs);
    return { requestId, displayNumber: correct, deviceChoices: choices };
  }
  /** Called by the user's phone. */
  async respond({ requestId, userId, choice, approve = true }) {
    let out = { ok: false, status: 'unknown' };
    await this.store.update(`push:${requestId}`, (r) => {
      if (!r || r.userId !== userId || r.expiresAt <= this.clock()) { out = { ok: false, status: 'expired_or_unknown' }; return undefined; }
      if (r.status !== 'pending') { out = { ok: false, status: r.status }; return undefined; }
      const status = approve && Number(choice) === r.correct ? 'approved' : 'denied';
      out = { ok: status === 'approved', status };
      return { ...r, status };
    });
    return out;
  }
  /** Called by the login page while polling. */
  async status(requestId) {
    const r = await this.store.get(`push:${requestId}`);
    return r && r.expiresAt > this.clock() ? r.status : 'expired';
  }
}
