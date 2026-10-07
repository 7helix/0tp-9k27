# Language ports and how they are kept honest

| Port | Location | Scope | Verification |
|---|---|---|---|
| Node (reference) | `src/` | everything | 200+ tests, RFC vectors |
| Python | `ports/python/` | HOTP, TOTP, verify (window + replay), Base32 | RFC vectors + cross-check (local and CI) |
| Java 17+ | `ports/java/OtpFortress.java` | same | RFC vectors + cross-check (local and CI) |
| Go 1.21+ | `ports/go/` | same | **CI only** (no Go toolchain was available where it was written): `go vet`, `go test`, cross-check |

## The cross-check
`node scripts/cross-check.js [cases] [seed]` generates random inputs and requires **byte-identical** output from every implementation whose toolchain exists.
Inputs include keys of 1-200 bytes (keys longer than the hash block size are hashed first - classic place for ports to diverge), all three hashes,
6-10 digits, time-step boundaries (29 999 ms vs 30 000 ms), and HOTP counters across the 2^32 boundary.
It caught nothing yet - which is the point of running it on every push.

## Batch protocol (how to add a port)
Provide a command that reads lines `totp|hotp <base32> <timeMs|counter> <digits> <SHA1|SHA256|SHA512>` from stdin and prints one code per line (`ERR` for invalid input), then add it to `IMPLS` in `scripts/cross-check.js`.
Port the RFC vectors from `tests/core.test.js` first.

## What is *not* ported
Challenge/magic-link/transaction OTPs, rate limiting, lockout, WebAuthn, the HTTP server. Ports are for verifying and generating standard OTPs inside other stacks; use the HTTP API (with the Python/JS clients) for the rest.
Wanted: Rust, PHP, C#, Kotlin (ROADMAP).
