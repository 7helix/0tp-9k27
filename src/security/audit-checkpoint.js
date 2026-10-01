// The hash chain proves *internal* consistency, but an attacker who controls the box can rewrite the
// whole chain or truncate the tail. Signed checkpoints, published to somewhere the attacker can't reach
// (another host, object-lock bucket, transparency log), close that gap.
import crypto from 'node:crypto';
import { AuditLog } from './audit-log.js';

export class AuditCheckpointer {
  /** privateKey: Ed25519 KeyObject/PEM. Keep it OFF the OTP server (sign from a separate process/HSM). */
  constructor({ privateKey, clock = Date.now }) { this.privateKey = privateKey; this.clock = clock; }
  static generateKeys() {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
    return { publicKey, privateKey };
  }
  #payload = (c) => Buffer.from(JSON.stringify([c.seq, c.headHash, c.ts]));
  checkpoint(entries) {
    if (!entries.length) throw new Error('nothing to checkpoint');
    const last = entries[entries.length - 1];
    const cp = { seq: last.seq, headHash: last.hash, ts: this.clock() };
    return { ...cp, sig: crypto.sign(null, this.#payload(cp), this.privateKey).toString('base64url') };
  }
  /** Verifies signature AND that `entries` still contains that exact head (detects rewrite + truncation). */
  static verify(cp, publicKey, entries) {
    const payload = Buffer.from(JSON.stringify([cp.seq, cp.headHash, cp.ts]));
    if (!crypto.verify(null, payload, publicKey, Buffer.from(cp.sig, 'base64url'))) return { ok: false, reason: 'bad_signature' };
    if (entries.length <= cp.seq) return { ok: false, reason: 'truncated' };
    if (entries[cp.seq].hash !== cp.headHash) return { ok: false, reason: 'history_rewritten' };
    const chain = AuditLog.verify(entries.slice(0, cp.seq + 1));
    return chain.ok ? { ok: true } : { ok: false, reason: 'chain_broken', brokenAt: chain.brokenAt };
  }
}
