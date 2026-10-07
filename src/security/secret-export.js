// Export and import secrets protected by a passphrase, for example to let someone back up their
// TOTP secrets or move them to a new server. scrypt turns the passphrase into a key, AES-256-GCM
// does the encryption. The result is JSON that is safe to store or email.
import crypto from 'node:crypto';

const PARAMS = { N: 2 ** 15, r: 8, p: 1, maxmem: 64 * 1024 * 1024 };

export function exportSecrets(data, passphrase) {
  if (typeof passphrase !== 'string' || passphrase.length < 12) {
    throw new Error('passphrase must be at least 12 characters');
  }

  const salt = crypto.randomBytes(16);
  const iv = crypto.randomBytes(12);
  const key = crypto.scryptSync(passphrase, salt, 32, PARAMS);

  // the KDF parameters go in as authenticated data, so they can't be tampered with
  const meta = { v: 1, kdf: 'scrypt', N: PARAMS.N, r: PARAMS.r, p: PARAMS.p, salt: salt.toString('base64url') };
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  cipher.setAAD(Buffer.from(JSON.stringify(meta)));
  const ciphertext = Buffer.concat([cipher.update(JSON.stringify(data)), cipher.final()]);

  return JSON.stringify({
    ...meta,
    iv: iv.toString('base64url'),
    tag: cipher.getAuthTag().toString('base64url'),
    ct: ciphertext.toString('base64url'),
  });
}

export function importSecrets(envelope, passphrase) {
  const parsed = JSON.parse(envelope);
  if (parsed.v !== 1 || parsed.kdf !== 'scrypt') throw new Error('unsupported export format');

  // the envelope is untrusted input, so don't let it pick absurd scrypt costs
  if (parsed.N > 2 ** 20 || parsed.r > 16 || parsed.p > 4) throw new Error('KDF parameters too expensive');

  const key = crypto.scryptSync(passphrase, Buffer.from(parsed.salt, 'base64url'), 32, {
    N: parsed.N,
    r: parsed.r,
    p: parsed.p,
    maxmem: 512 * 1024 * 1024,
  });

  const decipher = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(parsed.iv, 'base64url'));
  const meta = { v: parsed.v, kdf: parsed.kdf, N: parsed.N, r: parsed.r, p: parsed.p, salt: parsed.salt };
  decipher.setAAD(Buffer.from(JSON.stringify(meta)));
  decipher.setAuthTag(Buffer.from(parsed.tag, 'base64url'));

  try {
    const plain = Buffer.concat([decipher.update(Buffer.from(parsed.ct, 'base64url')), decipher.final()]);
    return JSON.parse(plain.toString());
  } catch {
    throw new Error('wrong passphrase or corrupted export');
  }
}
