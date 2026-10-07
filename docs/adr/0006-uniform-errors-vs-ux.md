# ADR 0006 - Uniform verification errors by default
**Status:** accepted. **Context:** distinguishing "no such code", "expired" and "wrong" tells an attacker whether an account has a pending code (enumeration) and how many attempts remain.
**Decision:** HTTP verify routes return `invalid_or_expired` for those cases and omit `attemptsLeft`; `'strict'` mode also hides `not_enrolled`. Lockout-type reasons (`locked`, `rate_limited`, `too_many_attempts`, `suspicious_ip`) stay explicit because the UI must react to them.
**Consequences:** slightly vaguer UI copy. Library users calling the service directly still get detailed reasons - map them yourself at your own boundary.
