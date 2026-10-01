# Testing guide
```bash
npm test                                   # everything (Node built-in runner, 110 tests)
node --test tests/core.test.js             # one file
node scripts/verify-repo.js                # links, exports, zero-deps
(cd ports/python && python3 -m unittest)   # Python port
```
**Patterns used here**
- *Official vectors* (RFC 4226/6238) prove correctness. Add vectors first when porting.
- *Injected clock* (`clock: () => c.t`) makes expiry, lockout and windows deterministic - never `sleep()` in tests.
- *Attack tests*: parallel guessing, replay, tampering, cross-user ciphertext copy, forged tokens.
- *Statistical tests*: chi-square uniformity of the RNG (thresholds far above the 0.001 critical value).
- *Fake `fetch`* for providers/captcha so no test touches the network.
- *Real server on port 0* for HTTP tests; `server.closeAllConnections()` in `finally`.
Mutation check: `npm run mutation` breaks 13 critical security lines one at a time (in a scratch copy) and fails if any change goes unnoticed by the tests.

**Fuzzing:** `tests/fuzz.test.js` uses a seeded PRNG. A failure prints `seed=...`; reproduce with `FUZZ_SEED=<n> npm test`. `npm run fuzz` runs it with a fresh random seed - run it in CI nightly.
**Software authenticator:** `tests/helpers/fake-authenticator.js` builds byte-exact WebAuthn responses and can forge wrong origins, rpIds, flags, counters and signatures.
**Raw HTTP paths:** `fetch()` normalises `..` segments; use `node:http` (see `rawStatus` in `tests/redteam.test.js`) to send hostile paths untouched.
