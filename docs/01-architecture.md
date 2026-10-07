# Architecture

```
            +-------------------------- HTTP API (src/http) --------------------------+
            |  x-api-key auth - 10KB body cap - no-store - generic 500s               |
            +------------------------------------+------------------------------------+
                                                 v
                                   OtpService (src/service)
        rate limit -> lockout -> verify -> replay guard -> audit  (one shared gate)
        +---------------+--------------+---------------+------------------+
        | otp-types/    | security/    | delivery/     | storage/         |
        | challenge     | rate-limiter | providers     | MemoryStore      |
        | totp (core/)  | lockout      | templates     | FileStore        |
        | magic-link    | audit-log    | (sms/email)   | RedisStore (ref) |
        | backup-codes  | risk-engine  |               | your own...      |
        | transaction   +--------------+---------------+------------------+
        | push-approval |
        | voice / CR / signed-token       core/: base32, hotp, totp, otpauth, secret-box, crypto-utils
        +---------------+
```

## Layers
- **core/** pure functions, no I/O, verified against RFC vectors. Read these first.
- **otp-types/** each OTP kind is independent and takes a `store` (dependency injection = easy tests, easy swaps).
- **security/** controls that wrap *any* OTP type.
- **service/** the opinionated, hardened combination.

## The Store contract (the one thing to implement for scale)
`get / set(ttl) / del / update(key, syncFn)`. `update` must be atomic - it is what makes the attempt counter,
replay guard and rate limiter safe against parallel requests. Tests `challenge OTP: parallel guesses...`
prove it.

## Secrets at rest
- TOTP seeds: AES-256-GCM (`core/secret-box.js`), key derived by HKDF from the master key, ciphertext bound to the user id via AAD.
- Email/SMS codes: never stored; only `HMAC(pepper, salt|user|purpose|code)`.
- Backup codes: scrypt hashes.
- Magic links: HMAC of the token.
