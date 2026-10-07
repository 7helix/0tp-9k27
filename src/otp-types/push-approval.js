// Push approval with number matching, which is what stops "MFA fatigue" (spamming prompts until
// someone taps approve). The login screen shows a number, the phone shows three, and the user has to
// pick the right one. A wrong tap denies the request for good.
import crypto from 'node:crypto';
import { randomBytes, b64url } from '../core/crypto-utils.js';

function shuffle(items) {
  const copy = [...items];
  for (let i = copy.length - 1; i > 0; i--) {
    const j = crypto.randomInt(0, i + 1);
    [copy[i], copy[j]] = [copy[j], copy[i]];
  }
  return copy;
}

export class PushApproval {
  constructor({ store, clock = Date.now }) {
    this.store = store;
    this.clock = clock;
  }

  async request({ userId, ttlMs = 120_000, context = {} }) {
    const requestId = b64url(randomBytes(16));
    const correct = crypto.randomInt(10, 100);

    const decoys = new Set();
    while (decoys.size < 2) {
      const candidate = crypto.randomInt(10, 100);
      if (candidate !== correct) decoys.add(candidate);
    }

    await this.store.set(`push:${requestId}`, {
      userId,
      correct,
      status: 'pending',
      expiresAt: this.clock() + ttlMs,
      context,
    }, ttlMs);

    return { requestId, displayNumber: correct, deviceChoices: shuffle([correct, ...decoys]) };
  }

  // Called by the user's phone.
  async respond({ requestId, userId, choice, approve = true }) {
    let outcome = { ok: false, status: 'unknown' };

    await this.store.update(`push:${requestId}`, (record) => {
      if (!record || record.userId !== userId || record.expiresAt <= this.clock()) {
        outcome = { ok: false, status: 'expired_or_unknown' };
        return undefined;
      }
      if (record.status !== 'pending') {
        outcome = { ok: false, status: record.status };
        return undefined;
      }

      const status = approve && Number(choice) === record.correct ? 'approved' : 'denied';
      outcome = { ok: status === 'approved', status };
      return { ...record, status };
    });

    return outcome;
  }

  // Called by the login page while it polls.
  async status(requestId) {
    const record = await this.store.get(`push:${requestId}`);
    return record && record.expiresAt > this.clock() ? record.status : 'expired';
  }
}
