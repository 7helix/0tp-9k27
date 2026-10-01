// Browser/Node-compatible TOTP using the Web Crypto API (no libraries). Also unit-tested in Node.
const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

export function base32ToBytes(str) {
  const clean = str.toUpperCase().replace(/[\s=-]/g, '');
  let bits = 0, value = 0; const out = [];
  for (const ch of clean) {
    const i = B32.indexOf(ch); if (i < 0) throw new Error('Invalid Base32');
    value = (value << 5) | i; bits += 5;
    if (bits >= 8) { out.push((value >>> (bits - 8)) & 255); bits -= 8; }
    value &= (1 << bits) - 1;
  }
  return new Uint8Array(out);
}

export async function hotpWeb(secretBytes, counter, { digits = 6, algorithm = 'SHA-1' } = {}) {
  const key = await crypto.subtle.importKey('raw', secretBytes, { name: 'HMAC', hash: algorithm }, false, ['sign']);
  const msg = new ArrayBuffer(8); new DataView(msg).setBigUint64(0, BigInt(counter));
  const h = new Uint8Array(await crypto.subtle.sign('HMAC', key, msg));
  const off = h[h.length - 1] & 15;
  const bin = ((h[off] & 0x7f) << 24) | (h[off + 1] << 16) | (h[off + 2] << 8) | h[off + 3];
  return String(bin % 10 ** digits).padStart(digits, '0');
}

export const totpWeb = (secretBytes, { time = Date.now(), step = 30, ...o } = {}) =>
  hotpWeb(secretBytes, Math.floor(time / 1000 / step), o);
