// Several encryption keys at once, so the master key can be rotated without downtime.
// Ciphertexts start with the id of the key that made them ("k2:v1...."). Old keys can still decrypt.
import { encrypt, decrypt } from '../core/secret-box.js';

export class KeyRing {
  constructor({ keys, current }) {
    if (!keys[current]) throw new Error('current key id not in ring');
    for (const key of Object.values(keys)) {
      if (key.length !== 32) throw new Error('all keys must be 32 bytes');
    }
    this.keys = keys;
    this.current = current;
  }

  encrypt(plaintext, aad = '') {
    return `k${this.current}:${encrypt(this.keys[this.current], plaintext, aad)}`;
  }

  decrypt(token, aad = '') {
    const match = /^k(\d+):(.+)$/.exec(token);
    if (!match || !this.keys[match[1]]) throw new Error('unknown key id');
    return decrypt(this.keys[match[1]], match[2], aad);
  }

  needsRotation(token) {
    return !token.startsWith(`k${this.current}:`);
  }

  // Re-encrypts under the current key. Run it over everything in the background, and once nothing
  // needs rotation any more the old key can be removed.
  rotate(token, aad = '') {
    if (!this.needsRotation(token)) return token;
    return this.encrypt(this.decrypt(token, aad), aad);
  }
}
