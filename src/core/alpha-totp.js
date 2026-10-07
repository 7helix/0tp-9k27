// Letters-and-digits TOTP. Same idea as RFC 6238, but a 5 character code is easier to type than
// 6 digits. It is Steam Guard style, so authenticator apps won't understand it.
import { hmac } from './crypto-utils.js';
import { totpCounter } from './totp.js';

export const STEAM_ALPHABET = '23456789BCDFGHJKMNPQRTVWXY';

export function alphaTotp(secret, { time = Date.now(), step = 30, length = 5, alphabet = STEAM_ALPHABET } = {}) {
  const message = Buffer.alloc(8);
  message.writeBigUInt64BE(BigInt(totpCounter(time, step)));

  const digest = hmac('sha1', secret, message);
  let number = digest.readUInt32BE(digest[digest.length - 1] & 0x0f) & 0x7fffffff;

  let code = '';
  for (let i = 0; i < length; i++) {
    code += alphabet[number % alphabet.length];
    number = Math.floor(number / alphabet.length);
  }
  return code;
}
