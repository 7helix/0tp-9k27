# Learn OTP in 7 steps
1. Run `node examples/01-totp-basic.js`, then read `src/core/hotp.js` (40 lines) - this *is* RFC 4226.
2. Read `tests/core.test.js` - see how official test vectors prove correctness.
3. Read `src/core/totp.js`: HOTP where counter = time/30.
4. Read `src/otp-types/challenge-otp.js`: why codes are random, hashed, bound, capped.
5. Break it: delete the `attempts` increment and watch `parallel guesses` fail.
6. Read `docs/03-threat-model.md`; for each row find the line of code and the test.
7. Add a new OTP type (see CONTRIBUTING.md) - e.g. an email OTP with a QR-scan approval.

# Production hardening checklist
- [ ] TLS everywhere; API only reachable from your backend
- [ ] Master key + pepper in a secret manager; rotation plan
- [ ] Shared atomic store (Redis/SQL) - not MemoryStore
- [ ] Real delivery provider + delivery-failure alerts + per-country SMS spend caps
- [ ] Audit log shipped to append-only storage; alert on `verify.locked_out` spikes
- [ ] Offer TOTP/push/passkeys; treat SMS as fallback
- [ ] Backup codes flow + support-recovery process that resists social engineering
- [ ] Independent security review
