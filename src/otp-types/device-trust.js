// "Remember this device for 30 days" without weakening 2FA: a signed, revocable, user-bound token.
import { sign, verify } from './signed-token.js';
import { randomBytes, b64url } from '../core/crypto-utils.js';

export class DeviceTrust {
  constructor({ store, key, clock = Date.now }) { Object.assign(this, { store, key, clock }); }
  #k = (u) => `devtrust:${u}`;

  async issue(userId, { ttlDays = 30, label = 'unknown device' } = {}) {
    const id = b64url(randomBytes(12)); const ttlMs = ttlDays * 86_400_000;
    await this.store.update(this.#k(userId), (cur) => ({ devices: [...(cur?.devices || []), { id, label, createdAt: this.clock() }] }), 366 * 86_400_000);
    return { id, token: sign(this.key, { u: userId, id }, { ttlMs, now: this.clock() }) };
  }
  async check(userId, token) {
    const v = verify(this.key, token, { now: this.clock() });
    if (!v.ok || v.payload.u !== userId) return { trusted: false };
    const rec = await this.store.get(this.#k(userId));
    return { trusted: !!rec?.devices.some((d) => d.id === v.payload.id), id: v.payload.id };
  }
  async list(userId) { return (await this.store.get(this.#k(userId)))?.devices ?? []; }
  async revoke(userId, id) { await this.store.update(this.#k(userId), (c) => (c ? { devices: c.devices.filter((d) => d.id !== id) } : undefined)); }
  async revokeAll(userId) { await this.store.del(this.#k(userId)); }
}
