// The hash chain shows the log is consistent with itself, but someone who controls the server can
// rewrite the whole chain or chop off the end. A signed checkpoint, kept somewhere they can't reach
// (another host, a write-once bucket), closes that gap.
import crypto from 'node:crypto';
import { AuditLog } from './audit-log.js';

function payloadOf(checkpoint) {
  return Buffer.from(JSON.stringify([checkpoint.seq, checkpoint.headHash, checkpoint.ts]));
}

export class AuditCheckpointer {
  // privateKey is an Ed25519 key. Keep it off the OTP server (sign from another machine or an HSM).
  constructor({ privateKey, clock = Date.now }) {
    this.privateKey = privateKey;
    this.clock = clock;
  }

  static generateKeys() {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
    return { publicKey, privateKey };
  }

  checkpoint(entries) {
    if (entries.length === 0) throw new Error('nothing to checkpoint');

    const last = entries[entries.length - 1];
    const checkpoint = { seq: last.seq, headHash: last.hash, ts: this.clock() };
    const signature = crypto.sign(null, payloadOf(checkpoint), this.privateKey);
    return { ...checkpoint, sig: signature.toString('base64url') };
  }

  // Checks the signature, then that the log still contains that exact head. A shorter log means it
  // was truncated, a different hash at that position means history was rewritten.
  static verify(checkpoint, publicKey, entries) {
    const signature = Buffer.from(checkpoint.sig, 'base64url');
    if (!crypto.verify(null, payloadOf(checkpoint), publicKey, signature)) {
      return { ok: false, reason: 'bad_signature' };
    }
    if (entries.length <= checkpoint.seq) return { ok: false, reason: 'truncated' };
    if (entries[checkpoint.seq].hash !== checkpoint.headHash) return { ok: false, reason: 'history_rewritten' };

    const chain = AuditLog.verify(entries.slice(0, checkpoint.seq + 1));
    if (!chain.ok) return { ok: false, reason: 'chain_broken', brokenAt: chain.brokenAt };
    return { ok: true };
  }
}
