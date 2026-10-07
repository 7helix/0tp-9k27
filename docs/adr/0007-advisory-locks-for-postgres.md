# ADR 0007 - Per-key advisory locks (not row locks or SERIALIZABLE) in the Postgres store
**Status:** accepted. **Context:** `update()` must be atomic including when the row does not exist yet (first failure creates the counter).
`SELECT ... FOR UPDATE` cannot lock a missing row; `SERIALIZABLE` needs retry loops and fails under hot-key contention; `INSERT ... ON CONFLICT` alone lets two writers
both compute from "absent".
**Decision:** each write transaction takes `pg_advisory_xact_lock(hashtextextended(key, 0))` first. **Consequences:** all writers of one key serialise, different keys do not;
needs PostgreSQL >= 11; two keys may share a 64-bit hash (harmless extra waiting). set/del take the lock too so they are linearisable with update.
Alternatives rejected: SERIALIZABLE + retries (complexity in every caller), `FOR UPDATE` + a pre-insert (extra writes, still racy on create), application-level locks (not multi-node).
