// Alphanumeric TOTP: same time-based idea as RFC 6238 but the output is letters+digits.
// Shorter codes (5 chars over a 26-char alphabet ~ 23.5 bits) are easier to type than long numbers.
// Note: this "Steam-style" variant is NOT interoperable with standard authenticator apps.
import { hmac } from './crypto-utils.js';
import { totpCounter } from './totp.js';

export const STEAM_ALPHABET = '23456789BCDFGHJKMNPQRTVWXY';

export function alphaTotp(secret, { time = Date.now(), step = 30, length = 5, alphabet = STEAM_ALPHABET } = {}) {
  const msg = Buffer.alloc(8);
  msg.writeBigUInt64BE(BigInt(totpCounter(time, step)));
  const h = hmac('sha1', secret, msg);
  let full = h.readUInt32BE(h[h.length - 1] & 0x0f) & 0x7fffffff;
  let out = '';
  for (let i = 0; i < length; i++) {
    out += alphabet[full % alphabet.length];
    full = Math.floor(full / alphabet.length);
  }
  return out;
}
