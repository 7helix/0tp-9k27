// Sign-in links. The token is 256 random bits, only a hash of it is stored, and it works once.
import { randomBytes, hmac, b64url } from '../core/crypto-utils.js';

export class MagicLink {
  constructor({ store, pepper, baseUrl, clock = Date.now }) {
    this.store = store;
    this.pepper = pepper;
    this.baseUrl = baseUrl;
    this.clock = clock;
  }

  #key(token) {
    return `ml:${hmac('sha256', this.pepper, token).toString('hex')}`;
  }

  async issue({ userId, purpose = 'login', ttlMs = 900_000 }) {
    const token = b64url(randomBytes(32));
    await this.store.set(this.#key(token), { userId, purpose, expiresAt: this.clock() + ttlMs }, ttlMs);

    // Serve the landing page with Referrer-Policy: no-referrer, and swap the token for a session
    // with a POST. Email scanners that prefetch links would otherwise use it up.
    return { token, url: `${this.baseUrl}/verify?token=${token}` };
  }

  async consume(token, { purpose = 'login' } = {}) {
    const key = this.#key(String(token));
    const record = await this.store.get(key);
    if (!record || record.purpose !== purpose || record.expiresAt <= this.clock()) return { ok: false };

    await this.store.del(key);
    return { ok: true, userId: record.userId };
  }
}
