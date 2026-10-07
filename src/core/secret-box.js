// AES-256-GCM for secrets at rest, like TOTP seeds. Output looks like v1.<iv>.<tag>.<ciphertext>.
//
// `aad` ties the ciphertext to something, usually the user id, so a ciphertext copied into
// another user's record fails to decrypt.
import crypto from 'node:crypto';

export function encrypt(masterKey, plaintext, aad = '') {
  if (masterKey.length !== 32) throw new Error('masterKey must be 32 bytes');

  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', masterKey, iv);
  cipher.setAAD(Buffer.from(aad));
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();

  return ['v1', iv, tag, ciphertext].map((part, i) => (i === 0 ? part : part.toString('base64url'))).join('.');
}

export function decrypt(masterKey, token, aad = '') {
  const [version, iv, tag, ciphertext] = token.split('.');
  if (version !== 'v1') throw new Error('Unknown secret-box version');

  const decipher = crypto.createDecipheriv('aes-256-gcm', masterKey, Buffer.from(iv, 'base64url'));
  decipher.setAAD(Buffer.from(aad));
  decipher.setAuthTag(Buffer.from(tag, 'base64url'));
  return Buffer.concat([decipher.update(Buffer.from(ciphertext, 'base64url')), decipher.final()]);
}
