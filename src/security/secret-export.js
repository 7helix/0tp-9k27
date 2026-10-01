// Passphrase-protected export/import (e.g. let a user back up their TOTP secrets, or move them to a new server).
// scrypt (memory-hard) -> AES-256-GCM. Envelope is JSON, safe to store or email.
import crypto from 'node:crypto';

const PARAMS = { N: 2 ** 15, r: 8, p: 1, maxmem: 64 * 1024 * 1024 };
export function exportSecrets(data, passphrase) {
  if (typeof passphrase !== 'string' || passphrase.length < 12) throw new Error('passphrase must be at least 12 characters');
  const salt = crypto.randomBytes(16), iv = crypto.randomBytes(12);
  const key = crypto.scryptSync(passphrase, salt, 32, PARAMS);
  const c = crypto.createCipheriv('aes-256-gcm', key, iv);
  const meta = { v: 1, kdf: 'scrypt', N: PARAMS.N, r: PARAMS.r, p: PARAMS.p, salt: salt.toString('base64url') };
  c.setAAD(Buffer.from(JSON.stringify(meta)));            // parameters are authenticated too
  const ct = Buffer.concat([c.update(JSON.stringify(data)), c.final()]);
  return JSON.stringify({ ...meta, iv: iv.toString('base64url'), tag: c.getAuthTag().toString('base64url'), ct: ct.toString('base64url') });
}
export function importSecrets(envelope, passphrase) {
  const e = JSON.parse(envelope);
  if (e.v !== 1 || e.kdf !== 'scrypt') throw new Error('unsupported export format');
  if (e.N > 2 ** 20 || e.r > 16 || e.p > 4) throw new Error('KDF parameters too expensive'); // DoS guard on untrusted input
  const key = crypto.scryptSync(passphrase, Buffer.from(e.salt, 'base64url'), 32, { N: e.N, r: e.r, p: e.p, maxmem: 512 * 1024 * 1024 });
  const d = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(e.iv, 'base64url'));
  d.setAAD(Buffer.from(JSON.stringify({ v: e.v, kdf: e.kdf, N: e.N, r: e.r, p: e.p, salt: e.salt })));
  d.setAuthTag(Buffer.from(e.tag, 'base64url'));
  try { return JSON.parse(Buffer.concat([d.update(Buffer.from(e.ct, 'base64url')), d.final()]).toString()); }
  catch { throw new Error('wrong passphrase or corrupted export'); }
}
