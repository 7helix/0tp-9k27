// Shamir's Secret Sharing over GF(256): split the master key into N shares so that any K reconstruct it
// and K-1 reveal NOTHING (information-theoretic). Give shares to different people/vaults.
// Share format: SSS1-<k>-<x:2hex>-<data hex>-<checksum:4hex>  (checksum catches typos, not malicious shares)
import { randomBytes, sha256hex } from '../core/crypto-utils.js';

const EXP = new Uint8Array(512), LOG = new Uint8Array(256);
(() => {
  let x = 1;
  for (let i = 0; i < 255; i++) {
    EXP[i] = x; LOG[x] = i;
    const xtime = ((x << 1) ^ (x & 0x80 ? 0x11b : 0)) & 0xff;
    x = x ^ xtime; // multiply by generator 3
  }
  for (let i = 255; i < 512; i++) EXP[i] = EXP[i - 255];
})();
const mul = (a, b) => (a === 0 || b === 0 ? 0 : EXP[LOG[a] + LOG[b]]);
const inv = (a) => { if (a === 0) throw new Error('inverse of 0'); return EXP[255 - LOG[a]]; };

export function split(secret, n, k) {
  if (!Buffer.isBuffer(secret) || secret.length === 0) throw new Error('secret must be a non-empty Buffer');
  if (!Number.isInteger(n) || !Number.isInteger(k) || k < 2 || k > n || n > 255) throw new Error('need 2 <= k <= n <= 255');
  const shares = Array.from({ length: n }, (_, i) => ({ x: i + 1, y: Buffer.alloc(secret.length) }));
  for (let pos = 0; pos < secret.length; pos++) {
    const coeffs = [secret[pos], ...randomBytes(k - 1)];       // random polynomial, constant term = secret byte
    for (const s of shares) {
      let y = 0;
      for (let d = coeffs.length - 1; d >= 0; d--) y = mul(y, s.x) ^ coeffs[d]; // Horner
      s.y[pos] = y;
    }
  }
  const fingerprint = sha256hex(secret).slice(0, 16);
  return { shares: shares.map((s) => encode(k, s)), fingerprint };
}

const encode = (k, s) => {
  const body = `SSS1-${k}-${s.x.toString(16).padStart(2, '0')}-${s.y.toString('hex')}`;
  return `${body}-${sha256hex(body).slice(0, 4)}`;
};
function decode(str) {
  const m = /^SSS1-(\d+)-([0-9a-f]{2})-([0-9a-f]+)-([0-9a-f]{4})$/.exec(String(str).trim());
  if (!m) throw new Error('malformed share');
  const body = `SSS1-${m[1]}-${m[2]}-${m[3]}`;
  if (sha256hex(body).slice(0, 4) !== m[4]) throw new Error('share checksum mismatch (typo?)');
  return { k: Number(m[1]), x: parseInt(m[2], 16), y: Buffer.from(m[3], 'hex') };
}

export function combine(shareStrings, { fingerprint } = {}) {
  const shares = shareStrings.map(decode);
  const { k } = shares[0];
  if (shares.some((s) => s.k !== k || s.y.length !== shares[0].y.length)) throw new Error('shares are from different splits');
  if (new Set(shares.map((s) => s.x)).size !== shares.length) throw new Error('duplicate shares');
  if (shares.length < k) throw new Error(`need at least ${k} shares`);
  const use = shares.slice(0, k);
  const out = Buffer.alloc(use[0].y.length);
  for (let pos = 0; pos < out.length; pos++) {
    let acc = 0;
    for (const si of use) {           // Lagrange interpolation at x = 0
      let num = 1, den = 1;
      for (const sj of use) if (sj !== si) { num = mul(num, sj.x); den = mul(den, sj.x ^ si.x); }
      acc ^= mul(si.y[pos], mul(num, inv(den)));
    }
    out[pos] = acc;
  }
  if (fingerprint && sha256hex(out).slice(0, 16) !== fingerprint) throw new Error('reconstruction failed fingerprint check (wrong/corrupt shares)');
  return out;
}
