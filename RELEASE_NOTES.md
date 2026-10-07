# Release Notes - 0TP-F0rtr3ss-9k27

Repository: https://github.com/rose2x/0tp-f0rtr3ss-9k27
License: MIT
Language: JavaScript (96.1%) + Python (2.8%)
Node requirement: >= 20

---

## 2.1.0 - Advanced Security
Status: Current (latest)
Latest commit: 2026-10-01T05:30:31Z
Commit author: oscer07

### Highlights
- WebAuthn / Passkeys support with CBOR codec (RFC 8949), registration and assertion verification for ES256, EdDSA, and RS256, single-use challenges, origin/rpId/UV checks, and signature-counter clone detection.
- Hardened HTTP layer with HMAC-signed requests, body-bound signatures, nonce and timestamp replay protection, CIDR allowlist, trusted-proxy client IP handling, strict anti-enumeration mode, and response-time padding.
- Security modules including Shamir secret sharing (GF(256)), Ed25519-signed audit checkpoints, hashcash proof-of-work, impossible-travel detection, and passphrase-encrypted secret export.
- Anomaly detector integrated into the service, plus OTP input normalization for non-Latin digits during verification.
- Runtime configuration support for HMAC keys, allowlists, proxies, WebAuthn options, and metrics via environment variables; the hardened stack boots via bin/server.js.
- JS and Python SDKs now include HMAC signing support.

### Quality and assurance
- Tests increased from 58 to 110, including seeded fuzzing, a red-team suite, CLI checks, and config tests.
- Mutation testing includes 13 security-critical mutations, all detected by the automated suite.
- Documentation expanded to 18 guides and 6 ADRs.

---

## 2.0.1
Status: Maintenance fix

### Fixes
- Fixed a `npm test` failure on Node 20 caused by a glob expansion issue.
- The test runner is now executed via `scripts/run-tests.js`, which works on any Node >= 18.

---

## 2.0.0 - Major Expansion
Status: Previous stable release

### New OTP types
- QR login
- Device trust
- Delayed recovery
- Step-up sessions
- HOTP device resync
- Alphanumeric TOTP

### Security improvements
- Key ring rotation
- Input validation
- Idempotency
- Anomaly detection
- Captcha gate

### Storage and delivery
- SQLite store via `node:sqlite`
- Delivery providers: Twilio, SendGrid, Telegram, and failover logic
- Internationalized messaging in 6 languages

### Platform additions
- JavaScript and Python SDKs
- Python port with stdlib-only HOTP/TOTP
- Browser authenticator demo
- Deployment templates for Docker, Compose, Kubernetes, nginx, and systemd

### Fixes
- Fixed TOTP delta reporting `-0` when the window is 0.

---

## 1.0.0 - Initial Release
Status: Foundation release

### Core features
- HOTP and TOTP
- Email OTP
- SMS OTP
- Voice OTP
- Magic links
- Backup codes
- Transaction-bound OTP
- Push number matching
- HTTP API
- CLI tool

---

## Repository status
This repository currently has no published GitHub release objects and no visible Git tags in the live repository metadata checked. The release history above is therefore reconstructed from the project changelog and commit history rather than GitHub Releases.

## Version summary
- 2.1.0: Current advanced security release
- 2.0.1: Node 20 compatibility fix
- 2.0.0: Large feature expansion release
- 1.0.0: Initial public version

## Project highlights
- Zero dependencies in the Node runtime
- RFC 4226 and 6238 verification in JS, Python, and browser implementations
- MIT license
- Strong focus on OTP learning, security hardening, and real-world usage

## Quick start
```bash
git clone https://github.com/rose2x/0tp-f0rtr3ss-9k27.git
cd 0tp-f0rtr3ss-9k27
npm install
npm test
npm run check
npm start
```

## Documentation
- docs/README.md
- docs/03-threat-model.md
- docs/14-webauthn-passkeys.md
- docs/15-advanced-hardening.md
- docs/18-red-team-playbook.md

## Disclaimer
This project is designed for learning and real-world use, and it includes a red-team suite plus fuzzing, but it is not independently audited.
