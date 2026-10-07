#!/usr/bin/env node
// Offline tools for the audit log. Run them on a machine that is NOT the OTP server.
//
//   keygen <dir>                          make an Ed25519 key pair (keep private.pem off the server)
//   sign   <audit.jsonl> <private.pem>    print a signed checkpoint for the current end of the log
//   verify <audit.jsonl> [--checkpoint cp.json --pubkey public.pem]
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { AuditLog, AuditCheckpointer } from '../src/index.js';

const [command, ...args] = process.argv.slice(2);

const readEntries = (file) => fs.readFileSync(file, 'utf8').split('\n').filter(Boolean).map((line) => JSON.parse(line));

function flag(name) {
  const at = args.indexOf(name);
  return at >= 0 ? args[at + 1] : undefined;
}

function die(message) {
  console.error(message);
  process.exit(1);
}

function keygen() {
  const dir = args[0] || '.';
  fs.mkdirSync(dir, { recursive: true });

  const { publicKey, privateKey } = AuditCheckpointer.generateKeys();
  fs.writeFileSync(path.join(dir, 'private.pem'), privateKey.export({ type: 'pkcs8', format: 'pem' }), { mode: 0o600 });
  fs.writeFileSync(path.join(dir, 'public.pem'), publicKey.export({ type: 'spki', format: 'pem' }));
  console.log(`wrote ${dir}/private.pem (keep it secret) and ${dir}/public.pem`);
}

function sign() {
  const entries = readEntries(args[0]);
  const chain = AuditLog.verify(entries);
  if (!chain.ok) die(`REFUSING to sign: chain already broken at entry ${chain.brokenAt}`);

  const privateKey = crypto.createPrivateKey(fs.readFileSync(args[1]));
  console.log(JSON.stringify(new AuditCheckpointer({ privateKey }).checkpoint(entries)));
}

function verify() {
  const entries = readEntries(args[0]);
  const chain = AuditLog.verify(entries);
  if (!chain.ok) die(`FAIL chain broken at entry ${chain.brokenAt}`);

  const checkpointFile = flag('--checkpoint');
  if (checkpointFile) {
    const checkpoint = JSON.parse(fs.readFileSync(checkpointFile, 'utf8'));
    const publicKey = crypto.createPublicKey(fs.readFileSync(flag('--pubkey')));
    const result = AuditCheckpointer.verify(checkpoint, publicKey, entries);
    if (!result.ok) die(`FAIL checkpoint: ${result.reason}`);
  }

  console.log(`OK ${entries.length} entries${checkpointFile ? ', checkpoint valid' : ''}`);
}

const commands = { keygen, sign, verify };

try {
  if (!commands[command]) {
    die('usage: audit-tool.js keygen <dir> | sign <audit.jsonl> <private.pem> | verify <audit.jsonl> [--checkpoint cp.json --pubkey public.pem]');
  }
  commands[command]();
} catch (err) {
  die(`error: ${err.message}`);
}
