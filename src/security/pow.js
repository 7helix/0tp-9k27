// Hashcash-style proof-of-work: makes mass-abuse of anonymous endpoints (SMS pumping, enumeration)
// cost CPU. Stateless challenge (HMAC-signed) + optional single-use tracking.
import crypto from 'node:crypto';
import { sign, verify } from '../otp-types/signed-token.js';
import { randomBytes, b64url, sha256 } from '../core/crypto-utils.js';

const leadingZeroBits = (buf) => {
  let bits = 0;
  for (const b of buf) { if (b === 0) { bits += 8; continue; } bits += Math.clz32(b) - 24; break; }
  return bits;
};

export class ProofOfWork {
  constructor({ key, store = null, clock = Date.now }) { Object.assign(this, { key, store, clock }); }
  issue({ bits = 18, ttlMs = 120_000, resource = '' } = {}) {
    const challenge = sign(this.key, { n: b64url(randomBytes(12)), b: bits, r: resource }, { ttlMs, now: this.clock() });
    return { challenge, bits };
  }
  async verify({ challenge, nonce, resource = '' }) {
    const v = verify(this.key, challenge, { now: this.clock() });
    if (!v.ok) return { ok: false, reason: v.reason || 'bad_challenge' };
    if (v.payload.r !== resource) return { ok: false, reason: 'wrong_resource' };
    if (leadingZeroBits(sha256(`${challenge}:${nonce}`)) < v.payload.b) return { ok: false, reason: 'insufficient_work' };
    if (this.store) {
      let first = false;
      await this.store.update(`pow:${v.payload.n}`, (c) => { if (c) return undefined; first = true; return { used: true }; }, 300_000);
      if (!first) return { ok: false, reason: 'already_used' };
    }
    return { ok: true };
  }
}
/** Client side (browser/app): find a nonce. Cost doubles with every extra bit. */
export function solve(challenge, bits, { maxIterations = 50_000_000 } = {}) {
  for (let n = 0; n < maxIterations; n++) if (leadingZeroBits(sha256(`${challenge}:${n}`)) >= bits) return String(n);
  throw new Error('no solution within maxIterations');
}
