#!/usr/bin/env node
// Poor-man's mutation testing: break one critical security line at a time in a scratch copy and make sure
// the tests NOTICE. A "SURVIVED" line means a security property has no test guarding it - add one.
// Usage: node scripts/mutation-check.js        (takes ~20-40 s)
import fs from 'node:fs'; import os from 'node:os'; import path from 'node:path';
import { fileURLToPath } from 'node:url'; import { spawnSync } from 'node:child_process';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const MUTATIONS = [
  ['attempt counter not incremented', 'src/otp-types/challenge-otp.js', 'attempts: r.attempts + 1', 'attempts: r.attempts', ['otp-types', 'redteam']],
  ['TOTP replay guard disabled', 'src/core/totp.js', 'if (c <= lastUsedCounter) replay = true;', 'if (false) replay = true;', ['core', 'redteam']],
  ['signed-request timestamp unchecked', 'src/http/signed-requests.js', 'Math.abs(now - Number(ts)) > skewMs', 'false', ['http-hardening']],
  ['signed-request nonce replay allowed', 'src/http/signed-requests.js', "return first ? { ok: true, keyId } : { ok: false, reason: 'replayed' };", 'return { ok: true, keyId };', ['http-hardening']],
  ['WebAuthn origin check removed', 'src/webauthn/webauthn.js', '!origins.includes(cd.origin)', 'false', ['webauthn']],
  ['WebAuthn rpId hash check removed', 'src/webauthn/webauthn.js', "if (!safeEqual(ad.rpIdHash.toString('hex'), sha256(rpId).toString('hex')))", 'if (false)', ['webauthn']],
  ['WebAuthn counter rollback ignored', 'src/webauthn/webauthn.js', 'ad.signCount <= credential.signCount) return', 'false) return', ['webauthn']],
  ['WebAuthn challenge not single-use', 'src/webauthn/webauthn.js', 'return r ? null : undefined; });\n    return taken', 'return undefined; });\n    return taken', ['webauthn']],
  ['uniform errors disabled', 'src/http/server.js', 'if (!mode || result?.ok !== false) return result;', 'return result;', ['http-hardening', 'redteam']],
  ['X-Forwarded-For trusted from anyone', 'src/http/cidr.js', 'if (!trustedProxies.length || !matchesAny(peer, trustedProxies)) return peer;', 'if (!trustedProxies.length) return peer;', ['http-hardening']],
  ['audit chain check weakened', 'src/security/audit-log.js', 'body.prev !== prev || body.seq !== i ||', '', ['security', 'advanced-security']],
  ['biased RNG', 'src/core/crypto-utils.js', 's += crypto.randomInt(0, 10);', 's += Math.floor(Math.random() * 10) % 7;', ['statistical']],
  ['cross-user ciphertext copy allowed (AAD dropped)', 'src/core/secret-box.js', 'decipher.setAAD(Buffer.from(aad));', '', ['core', 'redteam']],
];

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'mut-'));
fs.cpSync(root, tmp, { recursive: true, filter: (s) => !/node_modules|\.git$/.test(s) });
let survived = 0;
for (const [name, file, from, to, tests] of MUTATIONS) {
  const target = path.join(tmp, file); const original = fs.readFileSync(target, 'utf8');
  if (!original.includes(from)) { console.log(`STALE mutation (source changed): ${name}`); survived++; continue; }
  fs.writeFileSync(target, original.replace(from, to));
  const files = tests.map((t) => path.join('tests', `${t}.test.js`));
  const r = spawnSync(process.execPath, ['--test', ...files], { cwd: tmp, stdio: 'ignore' });
  fs.writeFileSync(target, original);
  if (r.status === 0) { survived++; console.log(`SURVIVED  ${name}`); } else console.log(`killed    ${name}`);
}
fs.rmSync(tmp, { recursive: true, force: true });
console.log(survived ? `\n${survived} mutation(s) not caught - add tests` : `\nall ${MUTATIONS.length} mutations caught`);
process.exit(survived ? 1 : 0);
