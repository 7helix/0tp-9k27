# Threat model (attack -> defense -> where/test)

| Attack | Defense | Where |
|---|---|---|
| Brute-forcing a 6-digit code (1M space) | 5 attempts per code, 10 verifies / 10 min, progressive lockout | challenge-otp, rate-limiter, lockout |
| Parallel guessing race | attempt counted **before** compare, inside atomic `update` | test "parallel guesses..." |
| Code replay | single use (deleted on success); TOTP `lastCounter` | totp.js, service |
| Stolen DB | codes stored only as peppered HMAC; TOTP seeds AES-GCM; backup codes scrypt | secret-box, challenge-otp |
| Code for purpose A used for B | purpose is part of the HMAC input | challenge-otp |
| Copying a ciphertext between users | AAD = userId | secret-box |
| Timing attacks | `safeEqual` (hash then `timingSafeEqual`), no early exits in HOTP window | crypto-utils |
| Modulo bias / predictable codes | `crypto.randomInt`, CSPRNG only | crypto-utils |
| SMS/email bombing & cost abuse | issue limiter per user+channel | rate-limiter |
| Push bombing / MFA fatigue | number matching, one wrong tap = denied | push-approval |
| Malware altering a payment | code bound to amount+currency+payee | transaction-otp |
| Real-time phishing relay | origin-bound SMS format; prefer WebAuthn | templates (partial mitigation) |
| Log leaks | audit redacts `code/secret/token`; masked destinations | audit-log, providers |
| Log tampering | hash-chained entries | audit-log |
| Body-size DoS / info leak | 10 KB cap, generic 500 | http/server |
| Clock skew | +/-1 step window only | totp.js |
| Real-time phishing relay of a code | **WebAuthn origin binding** (recommended factor) | webauthn/ |
| Cloned authenticator | signature counter must increase | webauthn/ |
| Leaked / replayed API credential | HMAC-signed, body-bound, nonce-protected requests | http/signed-requests.js |
| Untrusted network reaches the API | CIDR allowlist; `X-Forwarded-For` only via trusted proxies | http/cidr.js |
| Account enumeration | uniform verify errors, padded response time | http/server.js, security/timing.js |
| Credential stuffing | per-IP distinct-account detector | security/anomaly-detector.js |
| SMS pumping / bulk abuse | proof-of-work, CAPTCHA gate, issue limiter | security/pow.js, captcha-gate.js |
| Impossible-travel logins | haversine speed check feeding the risk engine | security/geo.js |
| Audit-log truncation or full rewrite by an intruder | signed checkpoints verified off-box | security/audit-checkpoint.js, bin/audit-tool.js |
| Loss / theft of the master key | Shamir split custody, key-ring rotation | security/shamir.js, key-ring.js |
| Hostile parser input | seeded fuzzing, hardened CBOR decoder | tests/fuzz.test.js, webauthn/cbor.js |

## Out of scope / residual risk
Real-time phishing proxies (Evilginx-style), SIM swap, compromised endpoints, insider access to master key.
Keep `OTP_MASTER_KEY` in a KMS/HSM/secret manager, rotate it, and never commit it.
