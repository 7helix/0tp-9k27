# 0TP-F0rtr3ss-9k27

An open-source toolkit for one-time passwords and related authentication, written in plain Node.js
with no runtime dependencies. It started as a way to learn how OTP systems work and grew into
something you can pull parts out of and use.

It covers HOTP and TOTP, email, SMS and voice codes, magic links, backup codes, push approval with
number matching, transaction-bound codes, QR login, and WebAuthn passkeys, plus the surrounding pieces
you need to run them safely: rate limiting, lockout, replay protection, encrypted secrets at rest, an
audit log, and an HTTP API.

Requires Node 20 or newer. The SQLite store needs Node 22.5 or newer.

## Try it

```bash
git clone <your-fork-url> 0TP-F0rtr3ss-9k27
cd 0TP-F0rtr3ss-9k27

npm test                 # the whole suite, including the official RFC test vectors
npm run example:totp     # a minimal TOTP example
npm run example:webauthn # a passkey login, and the same thing from a phishing origin
npm run check            # links, exports, no dependencies

node bin/otp-cli.js gen-key >> .env
npm start                # HTTP API on :8080
```

Other scripts: `npm run fuzz` (random garbage into every parser), `npm run mutation` (breaks 30
security-critical lines one at a time and checks the tests notice), `npm run cross-check` (compares the
Node, Python, Java and Go implementations on random inputs), `npm run test:stores` (the store
conformance suite, against real Postgres and Redis if `PG_URL` and `REDIS_URL` are set).

## Using it as a library

```js
import { OtpService, MemoryStore, ConsoleProvider, randomBytes } from './src/index.js';

const service = new OtpService({
  store: new MemoryStore(),
  masterKey: randomBytes(32),
  pepper: process.env.OTP_PEPPER,
  provider: new ConsoleProvider(),
  brand: 'MyApp',
  domain: 'myapp.com',
});

await service.sendOtp({ userId: 'u1', channel: 'email', to: 'me@example.com' });
await service.verifyOtp({ userId: 'u1', code: '123456' });
```

`MemoryStore` forgets everything on restart. For a single host use `SqliteStore`
(`src/storage/sqlite-store.js`), and for several servers `PostgresStore`. Anything that follows the
store contract in `src/storage/memory-store.js` works, and `tests/helpers/store-conformance.js` will
tell you whether yours does.

## What's in the box

**One-time codes and approvals:** HOTP, TOTP (SHA-1, SHA-256, SHA-512), alphanumeric TOTP, email/SMS/voice
codes, magic links, backup codes, transaction-bound codes, push approval with number matching,
challenge-response, signed step-up tokens, QR login, trusted devices, delayed account recovery, HOTP
hardware tokens with resync.

**Passkeys:** WebAuthn registration and login (ES256, EdDSA, RS256), origin and relying-party checks,
signature counter checks for cloned authenticators, and optional attestation (`packed`, `fido-u2f`)
against trust anchors you provide, with AAGUID allow and deny lists.

**Safety around all of it:** sliding-window rate limits, progressive lockout, AES-256-GCM for secrets,
key rotation, a hash-chained audit log with signed checkpoints, input validation, idempotency keys,
credential-stuffing detection, CAPTCHA gating, proof of work, Shamir splitting for the master key,
impossible-travel detection, passphrase-encrypted export.

**HTTP API:** static key or HMAC-signed requests, IP allowlists with proper proxy handling, identical
error responses to blunt account enumeration, optional response-time padding, Prometheus metrics.

**Stores:** memory, JSON file, SQLite, PostgreSQL, Redis.

**Delivery:** console, in-memory (for tests), webhook, Twilio, SendGrid, Telegram, failover between
providers, messages in six languages.

**Around the edges:** JavaScript and Python clients, a browser TOTP demo, Python/Java/Go ports of the
core HOTP/TOTP code, and Docker, Kubernetes, nginx and systemd templates.

## Layout

```
src/
  core/        base32, hotp, totp, alpha-totp, otpauth, secret-box, crypto-utils, entropy, format, drift
  otp-types/   challenge codes, magic links, backup codes, transaction, push, voice, QR login,
               device trust, recovery, step-up, HOTP devices, signed tokens
  security/    rate limiter, lockout, audit log and checkpoints, risk engine, key ring, validation,
               idempotency, anomaly detector, CAPTCHA gate, shamir, proof of work, geo, secret export
  storage/     memory, file, sqlite, postgres, redis
  delivery/    providers, templates, i18n, failover, twilio, sendgrid, telegram
  webauthn/    cbor, keys, webauthn, attestation
  http/        server, signed requests, cidr, metrics
  service/     otp-service, which ties the pieces together
bin/           otp-cli, audit-tool, server
clients/       JavaScript and Python clients
ports/         Python, Java and Go versions of the core
web/           browser TOTP demo
examples/      16 small runnable examples
tests/         unit tests, red-team tests, fuzzing, store conformance, helpers
deploy/        Dockerfile, compose files, Kubernetes, nginx, systemd
scripts/       test runner, repo check, mutation check, cross-language check, benchmarks
docs/          guides and design decisions (start at docs/README.md)
```

## Docs

Start with [docs/README.md](docs/README.md). Good next reads are the
[threat model](docs/03-threat-model.md), [choosing an OTP](docs/07-choosing-otp.md),
[advanced hardening](docs/15-advanced-hardening.md) and the [red-team playbook](docs/18-red-team-playbook.md).
Report security problems as described in [SECURITY.md](SECURITY.md). Ideas and plans are in
[ROADMAP.md](ROADMAP.md) and contribution notes in [CONTRIBUTING.md](CONTRIBUTING.md).

## Status

The code is tested against the RFC 4226 and 6238 vectors, a red-team suite, seeded fuzzing and mutation
checks. WebAuthn is tested against a software authenticator and attestation against certificates made
with the `openssl` command line, not against real browsers, security keys or vendor roots.

It has not had an independent security review, so have someone look at it before it protects anything
important.

Two things are only verified by CI and never ran on the author's machine: `PostgresStore` and
`RedisStore` against real servers (`.github/workflows/stores.yml`), and the Go port
(`.github/workflows/ports.yml`). Check that both jobs are green on your fork. The Docker, Kubernetes,
nginx and systemd files are templates that have not been run.

## License

MIT, see [LICENSE](LICENSE).
