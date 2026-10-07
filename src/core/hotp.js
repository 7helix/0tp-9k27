// HOTP, RFC 4226: one-time passwords from a shared secret and a counter.
import { hmac, algo, safeEqual } from './crypto-utils.js';

// Section 5.3 of the RFC. Also used by the other OTP types in this repo.
export function dynamicTruncate(hmacBuf, digits = 6) {
  if (!Number.isInteger(digits) || digits < 6 || digits > 10) throw new Error('digits must be 6..10');

  const offset = hmacBuf[hmacBuf.length - 1] & 0x0f;
  const binary = ((hmacBuf[offset] & 0x7f) << 24)
    | (hmacBuf[offset + 1] << 16)
    | (hmacBuf[offset + 2] << 8)
    | hmacBuf[offset + 3];

  return String(binary % 10 ** digits).padStart(digits, '0');
}

export function hotp(secret, counter, { digits = 6, algorithm = 'SHA1' } = {}) {
  const message = Buffer.alloc(8);
  message.writeBigUInt64BE(BigInt(counter));
  return dynamicTruncate(hmac(algo(algorithm), secret, message), digits);
}

// A hardware token can be pressed without logging in, so accept a few counters ahead.
// On success, store `nextCounter` so the same code can't be used again.
export function verifyHotp(secret, code, counter, { lookAhead = 5, digits = 6, algorithm = 'SHA1' } = {}) {
  let matched = -1;
  for (let i = 0; i <= lookAhead; i++) {
    const candidate = hotp(secret, counter + i, { digits, algorithm });
    // keep going after a match so the time taken doesn't show where it matched
    if (safeEqual(candidate, String(code)) && matched === -1) matched = i;
  }

  if (matched === -1) return { valid: false, nextCounter: counter };
  return { valid: true, nextCounter: counter + matched + 1 };
}
