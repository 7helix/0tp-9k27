// AES-256-GCM authenticated encryption for secrets at rest (e.g. TOTP seeds).
// Format: v1.<iv>.<tag>.<ciphertext>  (base64url parts)
// `aad` binds the ciphertext to a context (e.g. the user id) so a stolen
// ciphertext cannot be copied into another user's record.
import crypto from 'node:crypto';

export function encrypt(masterKey, plaintext, aad = '') {
  if (masterKey.length !== 32) throw new Error('masterKey must be 32 bytes');
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', masterKey, iv);
  cipher.setAAD(Buffer.from(aad));
  const ct = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();
  return `v1.${iv.toString('base64url')}.${tag.toString('base64url')}.${ct.toString('base64url')}`;
}

export function decrypt(masterKey, token, aad = '') {
  const [v, iv, tag, ct] = token.split('.');
  if (v !== 'v1') throw new Error('Unknown secret-box version');
  const decipher = crypto.createDecipheriv('aes-256-gcm', masterKey, Buffer.from(iv, 'base64url'));
  decipher.setAAD(Buffer.from(aad));
  decipher.setAuthTag(Buffer.from(tag, 'base64url'));
  return Buffer.concat([decipher.update(Buffer.from(ct, 'base64url')), decipher.final()]);
}
