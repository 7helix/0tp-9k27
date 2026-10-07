#!/usr/bin/env node
// Quick sanity check on the repo itself: no runtime dependencies, every relative link in the
// markdown files points at something, and every module in src/ is exported from src/index.js.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const SKIP_DIRS = new Set(['node_modules', '.git', '__pycache__']);

// modules that are deliberately not re-exported from index.js
const NOT_EXPORTED = new Set(['src/storage/sqlite-store.js', 'src/storage/index.js', 'src/index.js']);

let problems = 0;
function fail(message) {
  console.error(`FAIL ${message}`);
  problems++;
}

function listFiles(dir) {
  return fs.readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
    if (SKIP_DIRS.has(entry.name)) return [];
    const full = path.join(dir, entry.name);
    return entry.isDirectory() ? listFiles(full) : [full];
  });
}

const files = listFiles(root);

// 1. zero runtime dependencies
const pkg = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'));
if (pkg.dependencies && Object.keys(pkg.dependencies).length > 0) fail('package.json has runtime dependencies');

// 2. relative markdown links resolve (code blocks are ignored)
for (const file of files.filter((f) => f.endsWith('.md'))) {
  const text = fs.readFileSync(file, 'utf8').replace(/```[\s\S]*?```/g, '');
  for (const [, link] of text.matchAll(/\]\(([^)#\s]+)(?:#[^)]*)?\)/g)) {
    if (/^(https?:|mailto:)/.test(link)) continue;
    if (!fs.existsSync(path.resolve(path.dirname(file), link))) {
      fail(`${path.relative(root, file)} links to missing ${link}`);
    }
  }
}

// 3. everything in src/ is reachable from the index
const indexText = fs.readFileSync(path.join(root, 'src/index.js'), 'utf8');
const sourceFiles = files.filter((f) => f.includes(`${path.sep}src${path.sep}`) && f.endsWith('.js'));
for (const file of sourceFiles) {
  const relative = path.relative(root, file).split(path.sep).join('/');
  if (NOT_EXPORTED.has(relative)) continue;
  if (!indexText.includes(`./${relative.replace('src/', '')}`)) fail(`${relative} is not exported from src/index.js`);
}

const count = (pattern) => files.filter((f) => pattern.test(f)).length;
console.log(
  `files: ${files.length} | src modules: ${count(/\/src\/.*\.js$/)} | tests: ${count(/\.test\.js$/)} | docs: ${count(/\/docs\/.*\.md$/)}`,
);
console.log(problems ? `${problems} problem(s)` : 'repo self-check OK');
process.exit(problems ? 1 : 0);
