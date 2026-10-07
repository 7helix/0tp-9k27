// RFC 4648 Base32, the encoding authenticator apps use for TOTP secrets.
const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

export function base32Encode(buf, { padding = false } = {}) {
  let bits = 0;
  let value = 0;
  let out = '';

  for (const byte of buf) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
    value &= (1 << bits) - 1; // drop the bits we already emitted
  }
  if (bits > 0) out += ALPHABET[(value << (5 - bits)) & 31];

  if (padding) {
    while (out.length % 8) out += '=';
  }
  return out;
}

// Lenient on purpose: case, spaces, dashes and '=' padding are ignored, since people copy these by hand.
export function base32Decode(str) {
  const clean = String(str).toUpperCase().replace(/[\s=-]/g, '');
  const bytes = [];
  let bits = 0;
  let value = 0;

  for (const char of clean) {
    const index = ALPHABET.indexOf(char);
    if (index === -1) throw new Error('Invalid Base32 character');

    value = (value << 5) | index;
    bits += 5;
    if (bits >= 8) {
      bytes.push((value >>> (bits - 8)) & 255);
      bits -= 8;
    }
    value &= (1 << bits) - 1;
  }
  return Buffer.from(bytes);
}
