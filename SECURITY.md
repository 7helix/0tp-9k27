# Security Policy

## Reporting a vulnerability
Please **do not** open a public issue. Use GitHub's "Report a vulnerability" (private advisory) on this repo.
Include steps to reproduce and impact. We aim to acknowledge within 72 hours.

## Scope & honesty
This is an educational, open-source toolkit. It passes the RFC 4226 / RFC 6238 test vectors and ships
with tests for the attack classes in `docs/03-threat-model.md`, **but it has not had an independent
third-party audit**. Review it and pen-test your integration before protecting real money or identities.

## What has been tested
Official RFC vectors, attack simulations (`docs/18-red-team-playbook.md`), seeded fuzzing of every parser and the HTTP API, and a software WebAuthn authenticator.
Not tested: real browsers/security keys, real SMS/email gateways, load/soak behaviour, any third-party penetration test.

## Known limits
- `MemoryStore` / `FileStore` are single-process. Use a shared store with an atomic `update()` for multi-node deployments.
- `RedisStore` is a reference adapter - test it against your Redis.
- `deploy/` files are templates that were not executed in CI - review before use.
- Provider integrations (Twilio/SendGrid/Telegram) are verified against request shape with a fake `fetch`, not against the live APIs.
- WebAuthn supports attestation `none` only; it does not validate hardware attestation or FIDO metadata.
- Shamir sharing is implemented and tested here but not independently audited - use vetted tooling in regulated settings.
- SMS is inherently phishable and SIM-swappable; prefer TOTP/push/passkeys where you can.
