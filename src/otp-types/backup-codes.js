// Recovery codes: 10 single-use codes, ~50 bits each, stored as scrypt hashes.
import { randomFromAlphabet, scryptHash, scryptVerify } from '../core/crypto-utils.js';
import { UNAMBIGUOUS } from './challenge-otp.js';

export class BackupCodes {
  constructor({ store }) { this.store = store; }
  #key = (u) => `backup:${u}`;

  /** Returns plaintext codes ONCE. Regenerating replaces (invalidates) all old codes. */
  async generate(userId, count = 10) {
    const codes = Array.from({ length: count }, () => {
      const c = randomFromAlphabet(UNAMBIGUOUS, 10);
      return `${c.slice(0, 5)}-${c.slice(5)}`;
    });
    await this.store.set(this.#key(userId), { hashes: codes.map((c) => scryptHash(c.replace('-', ''))) });
    return codes;
  }
  async remaining(userId) { return (await this.store.get(this.#key(userId)))?.hashes.length ?? 0; }

  async consume(userId, code) {
    const key = this.#key(userId);
    const rec = await this.store.get(key);
    if (!rec) return { ok: false };
    const clean = String(code).toUpperCase().replace(/[\s-]/g, '');
    let idx = -1;
    rec.hashes.forEach((h, i) => { if (scryptVerify(clean, h) && idx === -1) idx = i; });
    if (idx === -1) return { ok: false };
    // Atomic removal: if two requests race with the same code, only one wins.
    let won = false;
    await this.store.update(key, (cur) => {
      if (!cur || !cur.hashes.includes(rec.hashes[idx])) return undefined;
      won = true;
      return { hashes: cur.hashes.filter((h) => h !== rec.hashes[idx]) };
    });
    return won ? { ok: true, remaining: (await this.remaining(userId)) } : { ok: false };
  }
}
