#!/usr/bin/env node
// Offline audit-log tooling. Run it on a machine that is NOT the OTP server.
//   keygen <dir>                         create Ed25519 checkpoint keys (keep private.pem off the server!)
//   sign   <audit.jsonl> <private.pem>   print a signed checkpoint for the current head
//   verify <audit.jsonl> [--checkpoint cp.json --pubkey public.pem]
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { AuditLog, AuditCheckpointer } from '../src/index.js';

const [cmd, ...args] = process.argv.slice(2);
const read = (f) => fs.readFileSync(f, 'utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l));
const flag = (n) => { const i = args.indexOf(n); return i >= 0 ? args[i + 1] : undefined; };
const die = (m) => { console.error(m); process.exit(1); };

try {
  if (cmd === 'keygen') {
    const dir = args[0] || '.'; fs.mkdirSync(dir, { recursive: true });
    const { publicKey, privateKey } = AuditCheckpointer.generateKeys();
    fs.writeFileSync(path.join(dir, 'private.pem'), privateKey.export({ type: 'pkcs8', format: 'pem' }), { mode: 0o600 });
    fs.writeFileSync(path.join(dir, 'public.pem'), publicKey.export({ type: 'spki', format: 'pem' }));
    console.log(`wrote ${dir}/private.pem (secret!) and ${dir}/public.pem`);
  } else if (cmd === 'sign') {
    const entries = read(args[0]); const chain = AuditLog.verify(entries);
    if (!chain.ok) die(`REFUSING to sign: chain already broken at entry ${chain.brokenAt}`);
    const cp = new AuditCheckpointer({ privateKey: crypto.createPrivateKey(fs.readFileSync(args[1])) }).checkpoint(entries);
    console.log(JSON.stringify(cp));
  } else if (cmd === 'verify') {
    const entries = read(args[0]); const chain = AuditLog.verify(entries);
    if (!chain.ok) die(`FAIL chain broken at entry ${chain.brokenAt}`);
    if (flag('--checkpoint')) {
      const r = AuditCheckpointer.verify(JSON.parse(fs.readFileSync(flag('--checkpoint'), 'utf8')), crypto.createPublicKey(fs.readFileSync(flag('--pubkey'))), entries);
      if (!r.ok) die(`FAIL checkpoint: ${r.reason}`);
    }
    console.log(`OK ${entries.length} entries${flag('--checkpoint') ? ', checkpoint valid' : ''}`);
  } else die('usage: audit-tool.js keygen <dir> | sign <audit.jsonl> <private.pem> | verify <audit.jsonl> [--checkpoint cp.json --pubkey public.pem]');
} catch (e) { die(`error: ${e.message}`); }
