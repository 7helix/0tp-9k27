# Documentation index
| Doc | What you learn |
|---|---|
| [01 Architecture](01-architecture.md) | layers, store contract, secrets at rest |
| [02 OTP types](02-otp-types.md) | all 12 core types side by side |
| [03 Threat model](03-threat-model.md) | attack -> defence -> code -> test |
| [04 HTTP API](04-api.md) | routes, bodies, reasons, status codes |
| [05 Learning path](05-learning-path.md) | 7 steps + production checklist |
| [06 Crypto explained](06-crypto-explained.md) | HMAC, truncation, entropy, replay |
| [07 Choosing an OTP](07-choosing-otp.md) | decision tree + trade-offs |
| [08 UX guidelines](08-ux-guidelines.md) | usability that helps security |
| [09 Standards notes](09-standards-notes.md) | RFCs, NIST, PSD2, WebOTP |
| [10 FAQ](10-faq.md) | common questions |
| [11 Glossary](11-glossary.md) | terms |
| [12 Key rotation](12-key-rotation.md) | rotate secrets without downtime |
| [13 Testing guide](13-testing-guide.md) | how the test-suite is built |
| [14 WebAuthn / passkeys](14-webauthn-passkeys.md) | the phishing-resistant factor, what is verified, limits |
| [15 Advanced hardening](15-advanced-hardening.md) | the full defence stack and a hardened server recipe |
| [16 Signed requests](16-signed-requests.md) | HMAC request-signing spec |
| [17 Secret sharing](17-secret-sharing.md) | Shamir split of the master key + ceremony checklist |
| [18 Red-team playbook](18-red-team-playbook.md) | 18 attacks mapped to tests |
| [19 WebAuthn attestation](19-webauthn-attestation.md) | restrict which hardware may enrol; the AAGUID rule |
| [20 Stores, Postgres, conformance](20-stores-postgres-conformance.md) | one test suite for every store; advisory-lock design |
| [21 Ports & cross-checking](21-ports-and-cross-checking.md) | Java/Go/Python ports and the cross-language checker |
| ADRs: [0001](adr/0001-zero-dependencies.md), [0002](adr/0002-store-contract.md), [0003](adr/0003-hmac-not-bcrypt.md), [0004](adr/0004-passkeys-none-attestation.md), [0005](adr/0005-hmac-signed-requests.md), [0006](adr/0006-uniform-errors-vs-ux.md), [0007](adr/0007-advisory-locks-for-postgres.md), [0008](adr/0008-attestation-trust-is-policy.md) | why key decisions were made |
