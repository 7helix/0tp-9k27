// Passwordless "magic link" tokens: 256-bit random, stored only as a hash, single use.
import { randomBytes, hmac, b64url } from '../core/crypto-utils.js';

export class MagicLink {
  constructor({ store, pepper, baseUrl, clock = Date.now }) { Object.assign(this, { store, pepper, baseUrl, clock }); }
  #id = (token) => `ml:${hmac('sha256', this.pepper, token).toString('hex')}`;

  async issue({ userId, purpose = 'login', ttlMs = 900_000 }) {
    const token = b64url(randomBytes(32));
    await this.store.set(this.#id(token), { userId, purpose, expiresAt: this.clock() + ttlMs }, ttlMs);
    // Put the token in the URL FRAGMENT-less query; serve the landing page with
    // `Referrer-Policy: no-referrer` and exchange it via POST so scanners/prefetchers can't burn it.
    return { token, url: `${this.baseUrl}/verify?token=${token}` };
  }
  async consume(token, { purpose = 'login' } = {}) {
    const id = this.#id(String(token));
    const rec = await this.store.get(id);
    if (!rec || rec.purpose !== purpose || rec.expiresAt <= this.clock()) return { ok: false };
    await this.store.del(id);
    return { ok: true, userId: rec.userId };
  }
}
