#!/usr/bin/env node
// Cross-version, cross-OS test runner. `node --test "glob"` only expands globs on Node >= 21 (and shells
// differ on Windows), so we list the files ourselves and pass explicit paths, which every Node >= 18 accepts.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const dir = path.join(root, 'tests');
const files = fs.readdirSync(dir).filter((f) => f.endsWith('.test.js')).sort().map((f) => path.join('tests', f));

if (files.length === 0) { console.error('No test files found in tests/'); process.exit(1); }
const r = spawnSync(process.execPath, ['--test', ...process.argv.slice(2), ...files], { cwd: root, stdio: 'inherit' });
process.exit(r.status ?? 1);
