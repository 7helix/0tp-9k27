// Hashcash style proof of work. It makes mass abuse of an open endpoint (SMS pumping, enumeration)
// cost real CPU time. The challenge is signed, so the server keeps no state unless you give it a
// store to make each challenge single use.
import { sign, verify } from '../otp-types/signed-token.js';
import { randomBytes, b64url, sha256 } from '../core/crypto-utils.js';

function leadingZeroBits(buf) {
  let bits = 0;
  for (const byte of buf) {
    if (byte === 0) {
      bits += 8;
      continue;
    }
    bits += Math.clz32(byte) - 24;
    break;
  }
  return bits;
}

export class ProofOfWork {
  constructor({ key, store = null, clock = Date.now }) {
    this.key = key;
    this.store = store;
    this.clock = clock;
  }

  issue({ bits = 18, ttlMs = 120_000, resource = '' } = {}) {
    const claims = { n: b64url(randomBytes(12)), b: bits, r: resource };
    const challenge = sign(this.key, claims, { ttlMs, now: this.clock() });
    return { challenge, bits };
  }

  async verify({ challenge, nonce, resource = '' }) {
    const verified = verify(this.key, challenge, { now: this.clock() });
    if (!verified.ok) return { ok: false, reason: verified.reason || 'bad_challenge' };

    const claims = verified.payload;
    if (claims.r !== resource) return { ok: false, reason: 'wrong_resource' };
    if (leadingZeroBits(sha256(`${challenge}:${nonce}`)) < claims.b) return { ok: false, reason: 'insufficient_work' };

    if (this.store) {
      let firstUse = false;
      await this.store.update(`pow:${claims.n}`, (existing) => {
        if (existing) return undefined;
        firstUse = true;
        return { used: true };
      }, 300_000);
      if (!firstUse) return { ok: false, reason: 'already_used' };
    }
    return { ok: true };
  }
}

// The client's side: look for a nonce. Every extra bit doubles the work.
export function solve(challenge, bits, { maxIterations = 50_000_000 } = {}) {
  for (let nonce = 0; nonce < maxIterations; nonce++) {
    if (leadingZeroBits(sha256(`${challenge}:${nonce}`)) >= bits) return String(nonce);
  }
  throw new Error('no solution within maxIterations');
}
