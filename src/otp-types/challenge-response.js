// Challenge-response token (OCRA-inspired, RFC 6287 style, simplified):
// server sends a random challenge, the token/app answers HMAC(secret, challenge).
// Nothing is replayable because every login has a fresh challenge.
import { hmac, algo, randomDigits, safeEqual } from '../core/crypto-utils.js';
import { dynamicTruncate } from '../core/hotp.js';

export const newChallenge = (len = 8) => randomDigits(len);
export function respond(secret, challenge, { digits = 8, algorithm = 'SHA256' } = {}) {
  return dynamicTruncate(hmac(algo(algorithm), secret, `CR|${challenge}`), digits);
}
export function verifyResponse(secret, challenge, response, opts) {
  return safeEqual(respond(secret, challenge, opts), String(response));
}
