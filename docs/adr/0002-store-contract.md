# ADR 0002 - A tiny store contract with an atomic `update`
**Status:** accepted. **Context:** attempt counters, replay guards and rate limiters are read-modify-write; naive get/set races
let parallel requests exceed limits. **Decision:** every store implements `get/set/del/update(key, syncFn)` and `update` must be atomic.
**Consequences:** any backend with a transaction or compare-and-swap qualifies (SQLite `BEGIN IMMEDIATE`, Redis `WATCH/MULTI`, SQL `SELECT ... FOR UPDATE`).
The callback must be synchronous so the critical section stays short and deadlock-free.
