<div align="center">

# 0TP-F0rtr3ss-9k27

**A zero-dependency, open-source authentication fortress: 18 kinds of OTPs & approvals, WebAuthn passkeys, a hardened API, tested, fuzzed and explained.**

`Node >= 20` - `0 dependencies` - `110 tests` - `RFC 4226 + 6238 verified in JS, Python & browser` - `MIT`

</div>

Built so developers can **learn** how strong OTP systems really work - and **use** any part in real projects.

## What's inside
| Area | Modules |
|---|---|
| **OTP types** | HOTP - TOTP (SHA1/256/512) - Alphanumeric TOTP - Email/SMS/Voice OTP - Alnum codes - Magic links - Backup codes - Transaction-bound OTP - Push + number matching - Challenge-response - Signed step-up tokens - **QR login - Device trust - Delayed account recovery - Step-up sessions - HOTP device resync** |
| **Passkeys** | **WebAuthn**: CBOR codec, registration + assertions (ES256/EdDSA/RS256), origin/rpId/UV checks, counter clone-detection, HTTP routes |
| **Security** | Rate limiter - Progressive lockout - Replay guards - AES-256-GCM secrets - **Key-ring rotation** - Hash-chained audit log - Risk engine - Input validation - Idempotency keys - Credential-stuffing detector - CAPTCHA gate - **Shamir key custody - Signed audit checkpoints - Proof-of-work - Impossible-travel - Encrypted secret export** |
| **Storage** | Memory - File - **SQLite (node:sqlite)** - Redis reference adapter - your own (atomic `update` contract) |
| **Delivery** | Console/Memory/Webhook - **Twilio - SendGrid - Telegram - Failover with circuit breaker - 6-language messages** |
| **HTTP hardening** | **HMAC-signed requests - CIDR allowlist + trusted proxies - uniform anti-enumeration errors - response-time padding - Prometheus metrics** |
| **Interfaces** | HTTP API - CLI - **audit tool** - **JS client - Python client - browser authenticator (WebCrypto)** |
| **Ports** | **Python (stdlib) HOTP/TOTP** verified against the same RFC vectors |
| **Ops** | **Dockerfile - Compose - Kubernetes - nginx - systemd** templates, benchmarks, repo self-check |

## Quick start
```bash
git clone <your-fork-url> 0TP-F0rtr3ss-9k27 && cd 0TP-F0rtr3ss-9k27
npm test                    # full suite incl. official RFC vectors
npm run check               # links, exports, zero-deps
npm run example:totp        # see it work
npm run example:webauthn    # passkeys vs a phishing origin
npm run fuzz                # fuzz every parser with a fresh seed
npm run mutation            # prove the tests catch 13 deliberately broken security lines
node bin/otp-cli.js gen-key >> .env
npm start                   # HTTP API on :8080
```

## Use as a library
```js
import { OtpService, MemoryStore, ConsoleProvider, randomBytes } from './src/index.js';

const svc = new OtpService({
  store: new MemoryStore(), masterKey: randomBytes(32), pepper: process.env.OTP_PEPPER,
  provider: new ConsoleProvider(), brand: 'MyApp', domain: 'myapp.com',
});
await svc.sendOtp({ userId: 'u1', channel: 'email', to: 'me@example.com' });
await svc.verifyOtp({ userId: 'u1', code: '123456' });
```
Durable storage on one host: `import { SqliteStore } from './src/storage/sqlite-store.js'` (Node >= 22.5).

## Repo map
```
0TP-F0rtr3ss-9k27/
|-- src/
|   |-- core/         base32, hotp, totp, alpha-totp, otpauth, secret-box, crypto-utils, entropy, format, drift
|   |-- otp-types/    challenge, magic-link, backup-codes, transaction, push, voice, challenge-response,
|   |                 signed-token, qr-login, device-trust, recovery-request, step-up-session, hotp-device
|   |-- security/     rate-limiter, lockout, audit-log, risk-engine, key-ring, input-validation,
|   |                 idempotency, anomaly-detector, captcha-gate, shamir, audit-checkpoint,
|   |                 timing, pow, geo, secret-export
|   |-- storage/      memory, file, sqlite, redis (reference)
|   |-- delivery/     providers, templates, i18n, failover, twilio, sendgrid, telegram
|   |-- service/      otp-service (the hardened orchestrator)
|   |-- webauthn/     cbor, webauthn (passkeys)
|   `-- http/         server, signed-requests, cidr, metrics
|-- clients/          js-client, python client, curl cheatsheet
|-- ports/python/     stdlib HOTP/TOTP + unit tests
|-- web/              WebCrypto TOTP module + authenticator demo page
|-- bin/              otp-cli.js, audit-tool.js, server.js
|-- examples/         15 runnable walkthroughs
|-- tests/            RFC vectors, red-team suite, seeded fuzzing, WebAuthn authenticator simulator, statistical/provider/client/CLI tests
|-- deploy/           Dockerfile, compose, k8s, nginx, systemd
|-- scripts/          verify-repo, bench, gen-vectors
`-- docs/             18 guides + 6 ADRs (see docs/README.md)
```

## Docs
Start at the [documentation index](docs/README.md), then [Threat model](docs/03-threat-model.md), [Advanced hardening](docs/15-advanced-hardening.md), [Red-team playbook](docs/18-red-team-playbook.md), [Choosing an OTP](docs/07-choosing-otp.md) and the [Learning path](docs/05-learning-path.md). Security reports: [SECURITY.md](SECURITY.md). Contributing: [CONTRIBUTING.md](CONTRIBUTING.md). Plans: [ROADMAP.md](ROADMAP.md).

## Honest disclaimer
Tested against RFC vectors, a red-team suite, seeded fuzzing and a *software* WebAuthn authenticator - but **not independently audited**, and never exercised against real browsers, security keys or SMS/email gateways. Deployment files (Docker/k8s/nginx/systemd) are templates I could not run in the build environment - review them. `RedisStore` is a reference adapter. Review everything before protecting anything critical.

MIT License.
