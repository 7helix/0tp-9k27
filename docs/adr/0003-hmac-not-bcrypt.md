# ADR 0003 - Peppered HMAC (not bcrypt/scrypt) for short-lived codes
**Status:** accepted. **Context:** a 6-digit code has only 10^6 possibilities, so *any* offline hash can be brute-forced instantly
if the attacker has both hash and salt; a slow KDF adds only a constant factor. **Decision:** store `HMAC-SHA256(pepper, salt|user|purpose|code)`.
The pepper lives outside the database, so a DB-only leak reveals nothing; codes expire in minutes; online guessing is capped by attempts + limiter.
**Contrast:** backup codes are long-lived and high-value, so they use scrypt. **Consequences:** if pepper AND database both leak within a code's TTL,
active codes are recoverable - hence short TTLs and single use.
