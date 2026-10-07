// Shamir's secret sharing over GF(256). Split a secret (say the master key) into N shares so that any
// K of them rebuild it and K-1 reveal nothing at all. Hand the shares to different people.
//
// A share looks like SSS1-<k>-<x>-<data hex>-<checksum>. The checksum catches typos, not malicious
// shares. For that, keep the fingerprint from split() and pass it to combine().
import { randomBytes, sha256hex } from '../core/crypto-utils.js';

// log/antilog tables for GF(256) with the AES polynomial (0x11b) and generator 3
const EXP = new Uint8Array(512);
const LOG = new Uint8Array(256);
{
  let x = 1;
  for (let i = 0; i < 255; i++) {
    EXP[i] = x;
    LOG[x] = i;
    const doubled = ((x << 1) ^ (x & 0x80 ? 0x11b : 0)) & 0xff;
    x ^= doubled; // multiply by 3
  }
  for (let i = 255; i < 512; i++) EXP[i] = EXP[i - 255];
}

function multiply(a, b) {
  if (a === 0 || b === 0) return 0;
  return EXP[LOG[a] + LOG[b]];
}

function inverse(a) {
  if (a === 0) throw new Error('inverse of 0');
  return EXP[255 - LOG[a]];
}

function encodeShare(k, share) {
  const body = `SSS1-${k}-${share.x.toString(16).padStart(2, '0')}-${share.y.toString('hex')}`;
  return `${body}-${sha256hex(body).slice(0, 4)}`;
}

function decodeShare(text) {
  const match = /^SSS1-(\d+)-([0-9a-f]{2})-([0-9a-f]+)-([0-9a-f]{4})$/.exec(String(text).trim());
  if (!match) throw new Error('malformed share');

  const body = `SSS1-${match[1]}-${match[2]}-${match[3]}`;
  if (sha256hex(body).slice(0, 4) !== match[4]) throw new Error('share checksum mismatch (typo?)');

  return { k: Number(match[1]), x: parseInt(match[2], 16), y: Buffer.from(match[3], 'hex') };
}

export function split(secret, n, k) {
  if (!Buffer.isBuffer(secret) || secret.length === 0) throw new Error('secret must be a non-empty Buffer');
  if (!Number.isInteger(n) || !Number.isInteger(k) || k < 2 || k > n || n > 255) {
    throw new Error('need 2 <= k <= n <= 255');
  }

  const shares = Array.from({ length: n }, (_, i) => ({ x: i + 1, y: Buffer.alloc(secret.length) }));

  // each byte of the secret gets its own random polynomial of degree k-1, with the byte as the constant term
  for (let pos = 0; pos < secret.length; pos++) {
    const coefficients = [secret[pos], ...randomBytes(k - 1)];
    for (const share of shares) {
      let y = 0;
      for (let degree = coefficients.length - 1; degree >= 0; degree--) {
        y = multiply(y, share.x) ^ coefficients[degree]; // Horner's method
      }
      share.y[pos] = y;
    }
  }

  const fingerprint = sha256hex(secret).slice(0, 16);
  return { shares: shares.map((share) => encodeShare(k, share)), fingerprint };
}

export function combine(shareStrings, { fingerprint } = {}) {
  const shares = shareStrings.map(decodeShare);
  const { k } = shares[0];

  if (shares.some((s) => s.k !== k || s.y.length !== shares[0].y.length)) {
    throw new Error('shares are from different splits');
  }
  if (new Set(shares.map((s) => s.x)).size !== shares.length) throw new Error('duplicate shares');
  if (shares.length < k) throw new Error(`need at least ${k} shares`);

  const used = shares.slice(0, k);
  const secret = Buffer.alloc(used[0].y.length);

  // Lagrange interpolation at x = 0 gives back the constant term of each polynomial
  for (let pos = 0; pos < secret.length; pos++) {
    let value = 0;
    for (const a of used) {
      let numerator = 1;
      let denominator = 1;
      for (const b of used) {
        if (b === a) continue;
        numerator = multiply(numerator, b.x);
        denominator = multiply(denominator, b.x ^ a.x);
      }
      value ^= multiply(a.y[pos], multiply(numerator, inverse(denominator)));
    }
    secret[pos] = value;
  }

  if (fingerprint && sha256hex(secret).slice(0, 16) !== fingerprint) {
    throw new Error('reconstruction failed fingerprint check (wrong/corrupt shares)');
  }
  return secret;
}
