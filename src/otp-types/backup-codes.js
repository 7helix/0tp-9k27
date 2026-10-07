// Recovery codes: ten single-use codes, about 50 bits each, stored as scrypt hashes.
import { randomFromAlphabet, scryptHash, scryptVerify } from '../core/crypto-utils.js';
import { UNAMBIGUOUS } from './challenge-otp.js';

export class BackupCodes {
  constructor({ store }) {
    this.store = store;
  }

  #key(userId) {
    return `backup:${userId}`;
  }

  // The plain codes are returned here and never again. Calling this replaces any older set.
  async generate(userId, count = 10) {
    const codes = [];
    for (let i = 0; i < count; i++) {
      const raw = randomFromAlphabet(UNAMBIGUOUS, 10);
      codes.push(`${raw.slice(0, 5)}-${raw.slice(5)}`);
    }
    const hashes = codes.map((code) => scryptHash(code.replace('-', '')));
    await this.store.set(this.#key(userId), { hashes });
    return codes;
  }

  async remaining(userId) {
    const record = await this.store.get(this.#key(userId));
    return record ? record.hashes.length : 0;
  }

  async consume(userId, code) {
    const key = this.#key(userId);
    const record = await this.store.get(key);
    if (!record) return { ok: false };

    const clean = String(code).toUpperCase().replace(/[\s-]/g, '');
    let matchIndex = -1;
    record.hashes.forEach((hash, i) => {
      if (scryptVerify(clean, hash) && matchIndex === -1) matchIndex = i;
    });
    if (matchIndex === -1) return { ok: false };

    // Remove it atomically. If two requests race with the same code, only one gets to remove it.
    const used = record.hashes[matchIndex];
    let won = false;
    await this.store.update(key, (current) => {
      if (!current || !current.hashes.includes(used)) return undefined;
      won = true;
      return { hashes: current.hashes.filter((hash) => hash !== used) };
    });

    if (!won) return { ok: false };
    return { ok: true, remaining: await this.remaining(userId) };
  }
}
