// TOTP in the browser with the Web Crypto API, no libraries. It also runs under Node, which is how
// the tests check it against the RFC vectors.
const BASE32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

export function base32ToBytes(text) {
  const clean = text.toUpperCase().replace(/[\s=-]/g, '');
  const bytes = [];
  let bits = 0;
  let value = 0;

  for (const char of clean) {
    const index = BASE32.indexOf(char);
    if (index < 0) throw new Error('Invalid Base32');

    value = (value << 5) | index;
    bits += 5;
    if (bits >= 8) {
      bytes.push((value >>> (bits - 8)) & 255);
      bits -= 8;
    }
    value &= (1 << bits) - 1;
  }
  return new Uint8Array(bytes);
}

export async function hotpWeb(secretBytes, counter, { digits = 6, algorithm = 'SHA-1' } = {}) {
  const key = await crypto.subtle.importKey('raw', secretBytes, { name: 'HMAC', hash: algorithm }, false, ['sign']);

  const message = new ArrayBuffer(8);
  new DataView(message).setBigUint64(0, BigInt(counter));
  const hash = new Uint8Array(await crypto.subtle.sign('HMAC', key, message));

  const offset = hash[hash.length - 1] & 15;
  const binary = ((hash[offset] & 0x7f) << 24)
    | (hash[offset + 1] << 16)
    | (hash[offset + 2] << 8)
    | hash[offset + 3];

  return String(binary % 10 ** digits).padStart(digits, '0');
}

export function totpWeb(secretBytes, { time = Date.now(), step = 30, ...options } = {}) {
  return hotpWeb(secretBytes, Math.floor(time / 1000 / step), options);
}
