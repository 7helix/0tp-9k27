// HOTP - RFC 4226 (counter-based one-time passwords)
import { hmac, algo, safeEqual } from './crypto-utils.js';

/** RFC 4226 section 5.3 dynamic truncation, reused by several OTP types in this repo. */
export function dynamicTruncate(hmacBuf, digits = 6) {
  if (!Number.isInteger(digits) || digits < 6 || digits > 10) throw new Error('digits must be 6..10');
  const off = hmacBuf[hmacBuf.length - 1] & 0x0f;
  const bin =
    ((hmacBuf[off] & 0x7f) << 24) |
    (hmacBuf[off + 1] << 16) |
    (hmacBuf[off + 2] << 8) |
    hmacBuf[off + 3];
  return String(bin % 10 ** digits).padStart(digits, '0');
}

export function hotp(secret, counter, { digits = 6, algorithm = 'SHA1' } = {}) {
  const msg = Buffer.alloc(8);
  msg.writeBigUInt64BE(BigInt(counter));
  return dynamicTruncate(hmac(algo(algorithm), secret, msg), digits);
}

/**
 * Verify with a look-ahead window (a hardware token may be pressed without logging in).
 * Returns { valid, nextCounter } - persist nextCounter so a code can never be reused.
 */
export function verifyHotp(secret, code, counter, { lookAhead = 5, digits = 6, algorithm = 'SHA1' } = {}) {
  let matched = -1;
  for (let i = 0; i <= lookAhead; i++) {
    const candidate = hotp(secret, counter + i, { digits, algorithm });
    if (safeEqual(candidate, String(code)) && matched === -1) matched = i; // no early exit
  }
  return matched === -1
    ? { valid: false, nextCounter: counter }
    : { valid: true, nextCounter: counter + matched + 1 };
}
