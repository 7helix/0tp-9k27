// Versioned encryption keys so you can ROTATE the master key without downtime.
// Ciphertexts are prefixed with the key id ("k2:v1.iv.tag.ct"); old keys stay decrypt-only.
import { encrypt, decrypt } from '../core/secret-box.js';

export class KeyRing {
  constructor({ keys, current }) {
    if (!keys[current]) throw new Error('current key id not in ring');
    for (const k of Object.values(keys)) if (k.length !== 32) throw new Error('all keys must be 32 bytes');
    Object.assign(this, { keys, current });
  }
  encrypt(plaintext, aad = '') { return `k${this.current}:${encrypt(this.keys[this.current], plaintext, aad)}`; }
  decrypt(token, aad = '') {
    const m = /^k(\d+):(.+)$/.exec(token);
    if (!m || !this.keys[m[1]]) throw new Error('unknown key id');
    return decrypt(this.keys[m[1]], m[2], aad);
  }
  needsRotation(token) { return !token.startsWith(`k${this.current}:`); }
  /** Re-encrypt under the current key (run as a background migration, then retire old keys). */
  rotate(token, aad = '') { return this.needsRotation(token) ? this.encrypt(this.decrypt(token, aad), aad) : token; }
}
