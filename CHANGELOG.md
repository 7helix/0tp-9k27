# Changelog
## 2.1.0 - advanced security
- **WebAuthn / passkeys**: CBOR codec (RFC 8949 vectors), registration + assertion verification (ES256, EdDSA, RS256), single-use challenges, origin/rpId/UV checks, signature-counter clone detection, HTTP routes
- **HTTP hardening**: HMAC-signed requests (body-bound, nonce + timestamp replay protection), CIDR allowlist, trusted-proxy client IP, uniform anti-enumeration errors (`'strict'` mode), response-time padding, Prometheus `/metrics`
- **Security modules**: Shamir secret sharing (GF(256)), Ed25519-signed audit checkpoints + `bin/audit-tool.js`, hashcash proof-of-work, impossible-travel detection, passphrase-encrypted secret export, key-material wiping
- Anomaly detector wired into the service (`anomaly`, per-request `ip`); OTP input normalisation (non-Latin digits) now applied on verify
- Config: HMAC keys, allowlists, proxies, WebAuthn, metrics via env; `bin/server.js` boots the hardened stack
- Clients: HMAC signing in the JS and Python SDKs (cross-language tested)
- `npm run mutation`: 13 security-critical mutations, all caught by the suite (runs in CI)
- Tests: 58 -> 110 incl. seeded fuzzing (`FUZZ_SEED`), a red-team suite, CLI and config tests. Docs 14-18, ADRs 0004-0006
## 2.0.0
- New OTP types: QR login, device trust, delayed recovery, step-up sessions, HOTP device resync, alphanumeric TOTP
- Security: key ring rotation, input validation, idempotency, anomaly detector, captcha gate
- Storage: SQLite store (node:sqlite). Delivery: Twilio, SendGrid, Telegram, failover, i18n (6 languages)
- Clients: JS + Python SDKs. Ports: Python. Web: browser authenticator demo
- Deploy templates: Docker, Compose, Kubernetes, nginx, systemd. Docs +8, ADRs +3
- Fix: TOTP `delta` no longer reports `-0` when `window` is 0
## 1.0.0
- Initial release: HOTP, TOTP, email/SMS/voice OTP, magic links, backup codes, transaction OTP, push number matching, HTTP API, CLI
## 2.0.1
- Fix: `npm test` failed on Node 20 (glob not expanded). Tests now run through `scripts/run-tests.js`, which works on any Node >= 18.
