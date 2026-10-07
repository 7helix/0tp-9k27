// Hardware-token style HOTP devices: encrypted seeds, a stored counter, and the resync procedure from
// RFC 4226 section 7.4 for tokens whose button was pressed many times and ran ahead of the server.
import { hotp, verifyHotp } from '../core/hotp.js';
import { safeEqual } from '../core/crypto-utils.js';
import { encrypt, decrypt } from '../core/secret-box.js';

export class HotpDevices {
  constructor({ store, key, lookAhead = 5, resyncWindow = 100 }) {
    this.store = store;
    this.key = key;
    this.lookAhead = lookAhead;
    this.resyncWindow = resyncWindow;
  }

  #key(deviceId) {
    return `hotpdev:${deviceId}`;
  }

  async register(deviceId, secret, { digits = 6, algorithm = 'SHA1' } = {}) {
    await this.store.set(this.#key(deviceId), {
      enc: encrypt(this.key, secret, deviceId),
      counter: 0,
      digits,
      algorithm,
    });
  }

  async verify(deviceId, code) {
    const device = await this.store.get(this.#key(deviceId));
    if (!device) return { ok: false, reason: 'unknown_device' };

    const secret = decrypt(this.key, device.enc, deviceId);
    const check = verifyHotp(secret, code, device.counter, {
      lookAhead: this.lookAhead,
      digits: device.digits,
      algorithm: device.algorithm,
    });
    if (!check.valid) return { ok: false, reason: 'invalid' };

    // advance the counter atomically so the same code can't be used twice in parallel
    let advanced = false;
    await this.store.update(this.#key(deviceId), (current) => {
      if (current.counter >= check.nextCounter) return undefined;
      advanced = true;
      return { ...current, counter: check.nextCounter };
    });
    return advanced ? { ok: true } : { ok: false, reason: 'replayed' };
  }

  // The user types two consecutive codes from the token and we search a wider range for the pair.
  async resync(deviceId, code1, code2) {
    const device = await this.store.get(this.#key(deviceId));
    if (!device) return { ok: false, reason: 'unknown_device' };

    const secret = decrypt(this.key, device.enc, deviceId);
    const options = { digits: device.digits, algorithm: device.algorithm };

    let found = -1;
    for (let counter = device.counter; counter <= device.counter + this.resyncWindow; counter++) {
      const first = safeEqual(hotp(secret, counter, options), String(code1));
      const second = safeEqual(hotp(secret, counter + 1, options), String(code2));
      if (first && second && found === -1) found = counter;
    }
    if (found === -1) return { ok: false, reason: 'no_match' };

    await this.store.set(this.#key(deviceId), { ...device, counter: found + 2 });
    return { ok: true, counter: found + 2 };
  }
}
