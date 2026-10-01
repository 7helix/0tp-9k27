// JSON-file persistence on top of MemoryStore. Good for demos, CLIs and single-node apps.
// Atomic write (tmp file + rename). Values must be JSON-serialisable.
import fs from 'node:fs';
import path from 'node:path';
import { MemoryStore } from './memory-store.js';

export class FileStore extends MemoryStore {
  constructor(filePath, opts = {}) {
    super(opts);
    this.filePath = filePath;
    fs.mkdirSync(path.dirname(filePath), { recursive: true });
    if (fs.existsSync(filePath)) {
      try { this._load(JSON.parse(fs.readFileSync(filePath, 'utf8'))); } catch { /* start empty */ }
    }
    this._changed = () => {
      const tmp = `${filePath}.${process.pid}.tmp`;
      fs.writeFileSync(tmp, JSON.stringify(this._dump()), { mode: 0o600 });
      fs.renameSync(tmp, filePath);
    };
  }
}
