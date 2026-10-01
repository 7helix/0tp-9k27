#!/usr/bin/env node
// Repo self-check: zero runtime deps, every relative markdown link resolves, every src module is exported.
import fs from 'node:fs'; import path from 'node:path'; import { fileURLToPath } from 'node:url';
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..'); let failed = 0;
const fail = (m) => { console.error(`FAIL ${m}`); failed++; };
const walk = (d) => fs.readdirSync(d, { withFileTypes: true }).flatMap((e) => e.name === 'node_modules' || e.name === '.git' ? [] : e.isDirectory() ? walk(path.join(d, e.name)) : [path.join(d, e.name)]);
const files = walk(root);

const pkg = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'));
if (pkg.dependencies && Object.keys(pkg.dependencies).length) fail('package.json has runtime dependencies');

for (const f of files.filter((x) => x.endsWith('.md'))) {
  const text = fs.readFileSync(f, 'utf8').replace(/```[\s\S]*?```/g, '');
  for (const [, link] of text.matchAll(/\]\(([^)#\s]+)(?:#[^)]*)?\)/g)) {
    if (/^(https?:|mailto:)/.test(link)) continue;
    if (!fs.existsSync(path.resolve(path.dirname(f), link))) fail(`${path.relative(root, f)} -> broken link ${link}`);
  }
}
const index = fs.readFileSync(path.join(root, 'src/index.js'), 'utf8');
const optional = new Set(['src/storage/sqlite-store.js', 'src/storage/index.js', 'src/index.js']);
for (const f of files.filter((x) => x.includes(`${path.sep}src${path.sep}`) && x.endsWith('.js'))) {
  const rel = path.relative(root, f).split(path.sep).join('/');
  if (!optional.has(rel) && !index.includes(`./${rel.replace('src/', '')}`)) fail(`${rel} is not exported from src/index.js`);
}
const count = (re) => files.filter((f) => re.test(f)).length;
console.log(`files: ${files.length} | src modules: ${count(/\/src\/.*\.js$/)} | tests: ${count(/\.test\.js$/)} | docs: ${count(/\/docs\/.*\.md$/)}`);
console.log(failed ? `${failed} problem(s)` : 'repo self-check OK');
process.exit(failed ? 1 : 0);
