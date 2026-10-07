# How HOTP/TOTP actually work (with the math)

**1. HMAC.** `HMAC(key, message)` gives a fixed-size tag that only someone with `key` can produce.
Server and phone share the `secret`; the message is an 8-byte big-endian **counter**.

**2. HOTP (RFC 4226).**
```
hash   = HMAC-SHA1(secret, counter)            // 20 bytes
offset = hash[19] & 0x0f                       // low 4 bits of the last byte -> 0..15
bin    = (hash[offset..offset+3] as uint32) & 0x7fffffff   // 31 bits, no sign bit
code   = bin mod 10^digits                     // pad with leading zeros
```
That is `dynamicTruncate()` in `src/core/hotp.js`. The random-looking offset spreads which bytes are used.

**3. TOTP (RFC 6238)** is HOTP with `counter = floor(unixSeconds / 30)`. Both sides agree on time, not on a counter.

**4. Why 6 digits is "enough".** There are 10^6 = 1,000,000 codes (~19.9 bits). That is tiny - security comes from
*limits on guessing*, not from the code being strong: 5 attempts => ~0.0005% chance (`docs` example 10 computes this).
A TOTP window of +/-1 accepts 3 codes at once, so the chance triples - still negligible under rate limits, disastrous without them.

**5. Why leading zeros matter.** `code` is a number; you must left-pad. A classic bug drops the zero and rejects ~10% of codes.

**6. Replay.** A TOTP code is valid for its whole 30 s step (plus window). Without recording the last accepted counter,
an attacker who shoulder-surfs or phishes a code can reuse it immediately. See `verifyTotp({ lastUsedCounter })`.

**7. Truncation bias.** `2^31 mod 10^6` is not zero, so digits are *very slightly* non-uniform (about 1 part in 2000). RFC 4226 accepts this; it is irrelevant next to the guess limits.

**8. Secret size.** RFC 4226 requires at least 128-bit secrets and recommends 160 bits (20 bytes). Enrollment uses `randomBytes(20)`.
