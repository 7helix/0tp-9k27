# ADR 0001 - Zero runtime dependencies
**Status:** accepted. **Context:** an auth library is a supply-chain target, and learners must be able to read *everything*.
**Decision:** use only `node:*` built-ins (crypto, http, fs, sqlite, test). **Consequences:** a little more code (HTTP router, base32)
but nothing to audit outside the repo and no transitive-dependency CVEs. `scripts/verify-repo.js` enforces it in CI.
