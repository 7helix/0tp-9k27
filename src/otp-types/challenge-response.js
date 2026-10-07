// Challenge-response, loosely based on OCRA (RFC 6287). The server sends a random challenge and the
// token answers with an HMAC of it. Every login has a fresh challenge, so there is nothing to replay.
import { hmac, algo, randomDigits, safeEqual } from '../core/crypto-utils.js';
import { dynamicTruncate } from '../core/hotp.js';

export function newChallenge(length = 8) {
  return randomDigits(length);
}

export function respond(secret, challenge, { digits = 8, algorithm = 'SHA256' } = {}) {
  return dynamicTruncate(hmac(algo(algorithm), secret, `CR|${challenge}`), digits);
}

export function verifyResponse(secret, challenge, response, options) {
  return safeEqual(respond(secret, challenge, options), String(response));
}
