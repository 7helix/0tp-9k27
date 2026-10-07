// Audit log where every entry carries the hash of the one before it. Editing or deleting an old
// line breaks every hash after it, which verify() reports. Fields that look like secrets are
// redacted before anything is written.
import fs from 'node:fs';
import path from 'node:path';
import { sha256hex } from '../core/crypto-utils.js';

const SECRET_FIELDS = /^(code|otp|secret|token|password|backupcode|seed)$/i;

export class AuditLog {
  constructor({ filePath = null, clock = Date.now } = {}) {
    this.filePath = filePath;
    this.clock = clock;
    this.entries = [];
    this.previousHash = 'GENESIS';

    if (filePath) fs.mkdirSync(path.dirname(filePath), { recursive: true });
  }

  #redact(data) {
    const clean = {};
    for (const [key, value] of Object.entries(data)) {
      clean[key] = SECRET_FIELDS.test(key) ? '[REDACTED]' : value;
    }
    return clean;
  }

  append(event, data = {}) {
    const body = {
      seq: this.entries.length,
      ts: this.clock(),
      event,
      data: this.#redact(data),
      prev: this.previousHash,
    };
    const entry = { ...body, hash: sha256hex(JSON.stringify(body)) };

    this.previousHash = entry.hash;
    this.entries.push(entry);
    if (this.filePath) fs.appendFileSync(this.filePath, JSON.stringify(entry) + '\n', { mode: 0o600 });
    return entry;
  }

  // Walks the chain from the start. Returns { ok: true } or { ok: false, brokenAt }.
  static verify(entries) {
    let previous = 'GENESIS';
    for (let i = 0; i < entries.length; i++) {
      const { hash, ...body } = entries[i];
      const intact = body.prev === previous && body.seq === i && sha256hex(JSON.stringify(body)) === hash;
      if (!intact) return { ok: false, brokenAt: i };
      previous = hash;
    }
    return { ok: true };
  }
}
