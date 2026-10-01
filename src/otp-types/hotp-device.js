// Manages hardware-token style HOTP devices: encrypted seeds, counter tracking and the
// two-consecutive-codes RESYNC procedure (RFC 4226 section 7.4) for devices that drifted far ahead.
import { hotp, verifyHotp } from '../core/hotp.js';
import { safeEqual } from '../core/crypto-utils.js';
import { encrypt, decrypt } from '../core/secret-box.js';

export class HotpDevices {
  constructor({ store, key, lookAhead = 5, resyncWindow = 100 }) { Object.assign(this, { store, key, lookAhead, resyncWindow }); }
  #k = (id) => `hotpdev:${id}`;

  async register(deviceId, secret, { digits = 6, algorithm = 'SHA1' } = {}) {
    await this.store.set(this.#k(deviceId), { enc: encrypt(this.key, secret, deviceId), counter: 0, digits, algorithm });
  }
  async verify(deviceId, code) {
    const d = await this.store.get(this.#k(deviceId));
    if (!d) return { ok: false, reason: 'unknown_device' };
    const secret = decrypt(this.key, d.enc, deviceId);
    const r = verifyHotp(secret, code, d.counter, { lookAhead: this.lookAhead, digits: d.digits, algorithm: d.algorithm });
    if (!r.valid) return { ok: false, reason: 'invalid' };
    let advanced = false;
    await this.store.update(this.#k(deviceId), (cur) => {
      if (cur.counter >= r.nextCounter) return undefined;
      advanced = true; return { ...cur, counter: r.nextCounter };
    });
    return advanced ? { ok: true } : { ok: false, reason: 'replayed' };
  }
  /** User types two consecutive codes from the token; we search a wider window for the pair. */
  async resync(deviceId, code1, code2) {
    const d = await this.store.get(this.#k(deviceId));
    if (!d) return { ok: false, reason: 'unknown_device' };
    const secret = decrypt(this.key, d.enc, deviceId);
    const opts = { digits: d.digits, algorithm: d.algorithm };
    let found = -1;
    for (let c = d.counter; c <= d.counter + this.resyncWindow; c++) {
      const a = safeEqual(hotp(secret, c, opts), String(code1));
      const b = safeEqual(hotp(secret, c + 1, opts), String(code2));
      if (a && b && found === -1) found = c;
    }
    if (found === -1) return { ok: false, reason: 'no_match' };
    await this.store.set(this.#k(deviceId), { ...d, counter: found + 2 });
    return { ok: true, counter: found + 2 };
  }
}
