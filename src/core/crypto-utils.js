// Small wrappers around node:crypto. No custom crypto primitives, ever.
import crypto from 'node:crypto';

export const ALGORITHMS = { SHA1: 'sha1', SHA256: 'sha256', SHA512: 'sha512' };

export function algo(name = 'SHA1') {
  const a = ALGORITHMS[String(name).toUpperCase()];
  if (!a) throw new Error(`Unsupported algorithm: ${name}`);
  return a;
}

export const sha256 = (data) => crypto.createHash('sha256').update(data).digest();
export const sha256hex = (data) => sha256(data).toString('hex');
export const hmac = (alg, key, data) => crypto.createHmac(alg, key).update(data).digest();

/** Constant-time string comparison (hashes first so lengths never leak). */
export function safeEqual(a, b) {
  return crypto.timingSafeEqual(sha256(String(a)), sha256(String(b)));
}

export const randomBytes = (n) => crypto.randomBytes(n);

/** Uniform random digits (crypto.randomInt is rejection-sampled: no modulo bias). */
export function randomDigits(n) {
  let s = '';
  for (let i = 0; i < n; i++) s += crypto.randomInt(0, 10);
  return s;
}

/** Uniform random string from an arbitrary alphabet. */
export function randomFromAlphabet(alphabet, n) {
  let s = '';
  for (let i = 0; i < n; i++) s += alphabet[crypto.randomInt(0, alphabet.length)];
  return s;
}

export const b64url = (buf) => Buffer.from(buf).toString('base64url');
export const fromB64url = (s) => Buffer.from(s, 'base64url');

/** HKDF-SHA256: derive independent sub-keys from one master key. */
export function hkdf(masterKey, info, length = 32) {
  return Buffer.from(crypto.hkdfSync('sha256', masterKey, Buffer.alloc(0), info, length));
}

/** scrypt hash for low-volume, high-value secrets (backup codes). */
export function scryptHash(secret, salt = crypto.randomBytes(16)) {
  const hash = crypto.scryptSync(secret, salt, 32, { N: 16384, r: 8, p: 1 });
  return `${salt.toString('base64url')}.${hash.toString('base64url')}`;
}
export function scryptVerify(secret, stored) {
  const [saltB64, hashB64] = stored.split('.');
  const expected = Buffer.from(hashB64, 'base64url');
  const actual = crypto.scryptSync(secret, Buffer.from(saltB64, 'base64url'), 32, { N: 16384, r: 8, p: 1 });
  return crypto.timingSafeEqual(expected, actual);
}

/** Best-effort zeroing of key material after use (JS cannot guarantee no copies, but this shortens exposure). */
export function wipe(buf) { if (Buffer.isBuffer(buf)) buf.fill(0); }
