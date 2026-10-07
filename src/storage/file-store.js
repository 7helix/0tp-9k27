// MemoryStore that saves itself to a JSON file after every change. Fine for demos, small CLIs and a
// single process. The file is written to a temp file first and renamed, so a crash can't leave half a file.
import fs from 'node:fs';
import path from 'node:path';
import { MemoryStore } from './memory-store.js';

export class FileStore extends MemoryStore {
  constructor(filePath, options = {}) {
    super(options);
    this.filePath = filePath;
    fs.mkdirSync(path.dirname(filePath), { recursive: true });

    if (fs.existsSync(filePath)) {
      try {
        this._load(JSON.parse(fs.readFileSync(filePath, 'utf8')));
      } catch {
        // unreadable file: start empty
      }
    }

    this._changed = () => {
      const tmp = `${filePath}.${process.pid}.tmp`;
      fs.writeFileSync(tmp, JSON.stringify(this._dump()), { mode: 0o600 });
      fs.renameSync(tmp, filePath);
    };
  }
}
