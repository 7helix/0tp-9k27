// "Remember this device for 30 days" without weakening 2FA. The cookie is a signed token that is
// tied to one user and can be revoked, because we also keep a record of every device we trusted.
import { sign, verify } from './signed-token.js';
import { randomBytes, b64url } from '../core/crypto-utils.js';

const YEAR_MS = 366 * 86_400_000;

export class DeviceTrust {
  constructor({ store, key, clock = Date.now }) {
    this.store = store;
    this.key = key;
    this.clock = clock;
  }

  #listKey(userId) {
    return `devtrust:${userId}`;
  }

  async issue(userId, { ttlDays = 30, label = 'unknown device' } = {}) {
    const id = b64url(randomBytes(12));
    const device = { id, label, createdAt: this.clock() };

    await this.store.update(this.#listKey(userId), (current) => ({
      devices: [...(current?.devices || []), device],
    }), YEAR_MS);

    const token = sign(this.key, { u: userId, id }, { ttlMs: ttlDays * 86_400_000, now: this.clock() });
    return { id, token };
  }

  async check(userId, token) {
    const verified = verify(this.key, token, { now: this.clock() });
    if (!verified.ok || verified.payload.u !== userId) return { trusted: false };

    const record = await this.store.get(this.#listKey(userId));
    const known = Boolean(record?.devices.some((device) => device.id === verified.payload.id));
    return { trusted: known, id: verified.payload.id };
  }

  async list(userId) {
    const record = await this.store.get(this.#listKey(userId));
    return record?.devices ?? [];
  }

  async revoke(userId, id) {
    await this.store.update(this.#listKey(userId), (current) => {
      if (!current) return undefined;
      return { devices: current.devices.filter((device) => device.id !== id) };
    });
  }

  async revokeAll(userId) {
    await this.store.del(this.#listKey(userId));
  }
}
