#!/usr/bin/env node
// Poor man's mutation testing. For each entry below we break one security-critical line in a scratch
// copy of the repo and run the tests that should notice. If they still pass, that property isn't
// really tested and we need another test.
//
//   node scripts/mutation-check.js      (takes a few minutes)
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

const MUTATIONS = [
  // Core and security
  {
    name: 'attempt counter not incremented',
    file: 'src/otp-types/challenge-otp.js',
    from: 'attempts: r.attempts + 1',
    to: 'attempts: r.attempts',
    tests: ['otp-types', 'redteam'],
  },
  {
    name: 'TOTP replay guard disabled',
    file: 'src/core/totp.js',
    from: 'if (counter <= lastUsedCounter) replayed = true;',
    to: 'if (false) replayed = true;',
    tests: ['core', 'redteam'],
  },
  // HTTP layer
  {
    name: 'signed-request timestamp unchecked',
    file: 'src/http/signed-requests.js',
    from: "if (Math.abs(now - Number(timestamp)) > skewMs) return { ok: false, reason: 'stale' };",
    to: '',
    tests: ['http-hardening'],
  },
  {
    name: 'signed-request nonce replay allowed',
    file: 'src/http/signed-requests.js',
    from: "return firstUse ? { ok: true, keyId } : { ok: false, reason: 'replayed' };",
    to: 'return { ok: true, keyId };',
    tests: ['http-hardening'],
  },
  // WebAuthn and attestation
  {
    name: 'WebAuthn origin check removed',
    file: 'src/webauthn/webauthn.js',
    from: "if (!origins.includes(clientData.origin)) return fail('origin_mismatch');",
    to: '',
    tests: ['webauthn'],
  },
  {
    name: 'WebAuthn rpId hash check removed',
    file: 'src/webauthn/webauthn.js',
    from: "if (!safeEqual(authData.rpIdHash.toString('hex'), expectedHash)) return fail('rp_id_mismatch');",
    to: '',
    tests: ['webauthn'],
  },
  {
    name: 'WebAuthn counter rollback ignored',
    file: 'src/webauthn/webauthn.js',
    from: "if (counterInUse && authData.signCount <= credential.signCount) return fail('sign_count_rollback');",
    to: '',
    tests: ['webauthn'],
  },
  {
    name: 'WebAuthn challenge not single-use',
    file: 'src/webauthn/webauthn.js',
    from: 'return record ? null : undefined;',
    to: 'return undefined;',
    tests: ['webauthn'],
  },
  // HTTP layer
  {
    name: 'uniform errors disabled',
    file: 'src/http/server.js',
    from: 'if (!mode || result?.ok !== false) return result;',
    to: 'return result;',
    tests: ['http-hardening', 'redteam'],
  },
  {
    name: 'X-Forwarded-For trusted from anyone',
    file: 'src/http/cidr.js',
    from: 'if (trustedProxies.length === 0 || !matchesAny(peer, trustedProxies)) return peer;',
    to: 'if (trustedProxies.length === 0) return peer;',
    tests: ['http-hardening'],
  },
  // Core and security
  {
    name: 'audit chain check weakened',
    file: 'src/security/audit-log.js',
    from: 'const intact = body.prev === previous && body.seq === i && sha256hex(JSON.stringify(body)) === hash;',
    to: 'const intact = sha256hex(JSON.stringify(body)) === hash;',
    tests: ['security', 'advanced-security'],
  },
  {
    name: 'biased RNG',
    file: 'src/core/crypto-utils.js',
    from: 's += crypto.randomInt(0, 10);',
    to: 's += Math.floor(Math.random() * 10) % 7;',
    tests: ['statistical'],
  },
  // WebAuthn and attestation
  {
    name: 'attestation: signature not verified (packed x5c)',
    file: 'src/webauthn/attestation.js',
    from: "if (!verifySignature({ alg, jwk, data: signedData, signature: sig })) return fail('bad_attestation_signature');",
    to: '',
    tests: ['attestation'],
  },
  {
    name: 'attestation: CA certificate accepted as leaf',
    file: 'src/webauthn/attestation.js',
    from: "if (leaf.ca) return fail('bad_attestation_cert');",
    to: '',
    tests: ['attestation'],
  },
  {
    name: 'attestation: chain never checked against anchors',
    file: 'src/webauthn/attestation.js',
    from: 'return top.checkIssued(anchor) && top.verify(anchor.publicKey);',
    to: 'return true;',
    tests: ['attestation'],
  },
  {
    name: 'attestation: certificate expiry ignored',
    file: 'src/webauthn/attestation.js',
    from: 'return new Date(cert.validFrom).getTime() <= now && now <= new Date(cert.validTo).getTime();',
    to: 'return true;',
    tests: ['attestation'],
  },
  {
    name: 'attestation: AAGUID allowlist not enforced',
    file: 'src/webauthn/attestation.js',
    from: 'if (policy.aaguidAllowlist && !policy.aaguidAllowlist.includes(effectiveAaguid)) {\n    return fail(\'aaguid_not_allowed\');\n  }',
    to: '',
    tests: ['attestation'],
  },
  {
    name: 'attestation: allowlist no longer implies a trusted chain',
    file: 'src/webauthn/attestation.js',
    from: 'policy.requireTrustedChain = Boolean(policy.requireTrustedChain || policy.aaguidAllowlist);',
    to: 'policy.requireTrustedChain = Boolean(policy.requireTrustedChain);',
    tests: ['attestation'],
  },
  {
    name: 'attestation: cert AAGUID mismatch ignored',
    file: 'src/webauthn/attestation.js',
    from: 'if (certAaguid !== null && certAaguid !== authDataAaguid) return fail',
    to: 'if (false) return fail',
    tests: ['attestation'],
  },
  // Stores and config
  {
    name: 'Postgres store: advisory lock removed',
    file: 'src/storage/postgres-store.js',
    from: "await client.query('SELECT pg_advisory_xact_lock(hashtextextended($1, 0))', [key]);",
    to: '',
    tests: ['stores'],
  },
  {
    name: 'Postgres store: update extends TTL',
    file: 'src/storage/postgres-store.js',
    from: 'if (row) exp = row.exp === null ? null : Number(row.exp);',
    to: '',
    tests: ['stores'],
  },
  {
    name: 'MemoryStore: values aliased (no copy on read)',
    file: 'src/storage/memory-store.js',
    from: 'return entry ? structuredClone(entry.value) : undefined;',
    to: 'return entry ? entry.value : undefined;',
    tests: ['stores'],
  },
  {
    name: 'config: production allowed without a durable store',
    file: 'src/config.js',
    from: 'if (production && !databaseUrl && !sqliteFile && !storeFile && !allowMemoryStore)',
    to: 'if (false)',
    tests: ['config'],
  },
  // Core and security
  {
    name: 'cross-user ciphertext copy allowed (AAD dropped)',
    file: 'src/core/secret-box.js',
    from: 'decipher.setAAD(Buffer.from(aad));',
    to: '',
    tests: ['core', 'redteam'],
  },
  // WebAuthn and attestation
  {
    name: 'attestation: wrong OU accepted',
    file: 'src/webauthn/attestation.js',
    from: "subject.OU === 'Authenticator Attestation'",
    to: 'true',
    tests: ['attestation'],
  },
  {
    name: 'attestation: self-attestation signature unchecked',
    file: 'src/webauthn/attestation.js',
    from: "return good ? { ok: true, type: 'self', trusted: null } : fail('bad_attestation_signature');",
    to: "return { ok: true, type: 'self', trusted: null };",
    tests: ['attestation'],
  },
  {
    name: 'attestation: fido-u2f signature unchecked',
    file: 'src/webauthn/attestation.js',
    from: 'if (!verifySignature({ alg: ALG.ES256, jwk, data: signedData, signature: sig })) {\n    return fail(\'bad_attestation_signature\');\n  }',
    to: '',
    tests: ['attestation'],
  },
  {
    name: 'attestation: AAGUID denylist not enforced',
    file: 'src/webauthn/attestation.js',
    from: "if (policy.aaguidDenylist.includes(aaguid)) return fail('aaguid_not_allowed');",
    to: '',
    tests: ['attestation'],
  },
  {
    name: 'attestation: default policy no longer none-only',
    file: 'src/webauthn/attestation.js',
    from: 'formats: [\'none\'],\n  trustAnchors: [],',
    to: 'formats: [\'none\', \'packed\'],\n  trustAnchors: [],',
    tests: ['attestation'],
  },
  // Stores and config
  {
    name: 'postgres: connection leaked',
    file: 'src/storage/postgres-store.js',
    from: 'client.release();',
    to: '',
    tests: ['stores'],
  },
];

const scratch = fs.mkdtempSync(path.join(os.tmpdir(), 'mut-'));
fs.cpSync(root, scratch, { recursive: true, filter: (p) => !/node_modules|\.git$/.test(p) });

let problems = 0;

for (const mutation of MUTATIONS) {
  const target = path.join(scratch, mutation.file);
  const original = fs.readFileSync(target, 'utf8');

  if (!original.includes(mutation.from)) {
    console.log(`STALE     ${mutation.name} (the source has changed, update the entry)`);
    problems++;
    continue;
  }

  fs.writeFileSync(target, original.replace(mutation.from, mutation.to));
  const testFiles = mutation.tests.map((name) => path.join('tests', `${name}.test.js`));
  const run = spawnSync(process.execPath, ['--test', ...testFiles], { cwd: scratch, stdio: 'ignore' });
  fs.writeFileSync(target, original);

  if (run.status === 0) {
    console.log(`SURVIVED  ${mutation.name}`);
    problems++;
  } else {
    console.log(`killed    ${mutation.name}`);
  }
}

fs.rmSync(scratch, { recursive: true, force: true });

if (problems) {
  console.log(`\n${problems} mutation(s) not caught, add tests`);
  process.exit(1);
}
console.log(`\nall ${MUTATIONS.length} mutations caught`);
