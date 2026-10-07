// Thin wrappers around node:crypto. Nothing here is home-made crypto.
import crypto from 'node:crypto';

export const ALGORITHMS = { SHA1: 'sha1', SHA256: 'sha256', SHA512: 'sha512' };

export function algo(name = 'SHA1') {
  const found = ALGORITHMS[String(name).toUpperCase()];
  if (!found) throw new Error(`Unsupported algorithm: ${name}`);
  return found;
}

export const sha256 = (data) => crypto.createHash('sha256').update(data).digest();
export const sha256hex = (data) => sha256(data).toString('hex');
export const hmac = (alg, key, data) => crypto.createHmac(alg, key).update(data).digest();
export const randomBytes = (n) => crypto.randomBytes(n);
export const b64url = (buf) => Buffer.from(buf).toString('base64url');
export const fromB64url = (str) => Buffer.from(str, 'base64url');

// Compares in constant time. Both sides are hashed first so a length difference doesn't leak either.
export function safeEqual(a, b) {
  return crypto.timingSafeEqual(sha256(String(a)), sha256(String(b)));
}

// crypto.randomInt rejects values that would cause modulo bias, so every digit is uniform.
export function randomDigits(count) {
  let digits = '';
  for (let i = 0; i < count; i++) digits += crypto.randomInt(0, 10);
  return digits;
}

export function randomFromAlphabet(alphabet, count) {
  let out = '';
  for (let i = 0; i < count; i++) out += alphabet[crypto.randomInt(0, alphabet.length)];
  return out;
}

// Derives independent sub-keys from one master key.
export function hkdf(masterKey, info, length = 32) {
  return Buffer.from(crypto.hkdfSync('sha256', masterKey, Buffer.alloc(0), info, length));
}

// scrypt is for secrets that live a long time and can't be rate limited offline, like backup codes.
const SCRYPT = { N: 16384, r: 8, p: 1 };

export function scryptHash(secret, salt = crypto.randomBytes(16)) {
  const hash = crypto.scryptSync(secret, salt, 32, SCRYPT);
  return `${salt.toString('base64url')}.${hash.toString('base64url')}`;
}

export function scryptVerify(secret, stored) {
  const [salt, expected] = stored.split('.');
  const actual = crypto.scryptSync(secret, Buffer.from(salt, 'base64url'), 32, SCRYPT);
  return crypto.timingSafeEqual(Buffer.from(expected, 'base64url'), actual);
}

// Zeroes a buffer once we're done with it. JS can't promise there are no other copies,
// but it shortens how long key material sits around.
export function wipe(buf) {
  if (Buffer.isBuffer(buf)) buf.fill(0);
}
