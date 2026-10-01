// Tamper-evident audit log: every entry contains the hash of the previous one
// (a tiny blockchain-style chain). Editing or deleting any past line breaks verification.
// Secrets are NEVER logged - sensitive keys are redacted defensively.
import fs from 'node:fs';
import path from 'node:path';
import { sha256hex } from '../core/crypto-utils.js';

const REDACT = /^(code|otp|secret|token|password|backupcode|seed)$/i;

export class AuditLog {
  constructor({ filePath = null, clock = Date.now } = {}) {
    this.filePath = filePath;
    this.clock = clock;
    this.entries = [];
    this.prev = 'GENESIS';
    if (filePath) fs.mkdirSync(path.dirname(filePath), { recursive: true });
  }
  #clean(obj) {
    return Object.fromEntries(Object.entries(obj).map(([k, v]) => [k, REDACT.test(k) ? '[REDACTED]' : v]));
  }
  append(event, data = {}) {
    const body = { seq: this.entries.length, ts: this.clock(), event, data: this.#clean(data), prev: this.prev };
    const entry = { ...body, hash: sha256hex(JSON.stringify(body)) };
    this.prev = entry.hash;
    this.entries.push(entry);
    if (this.filePath) fs.appendFileSync(this.filePath, JSON.stringify(entry) + '\n', { mode: 0o600 });
    return entry;
  }
  static verify(entries) {
    let prev = 'GENESIS';
    for (const [i, e] of entries.entries()) {
      const { hash, ...body } = e;
      if (body.prev !== prev || body.seq !== i || sha256hex(JSON.stringify(body)) !== hash) {
        return { ok: false, brokenAt: i };
      }
      prev = hash;
    }
    return { ok: true };
  }
}
