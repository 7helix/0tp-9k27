# Stores, Postgres, and the conformance suite

Every guarantee in this repo (attempt budgets, replay guards, rate limits, single-use challenges) is only as strong as the store's
`update()`. So the store contract is **tested, not documented**: `tests/helpers/store-conformance.js` is one behavioural suite that every store must pass.

| Store | Use for | Verified here |
|---|---|---|
| `MemoryStore` | tests, single-process demos | conformance suite |
| `FileStore` | demos / CLIs | conformance suite |
| `SqliteStore` | one host, durable (Node >= 22.5) | conformance suite |
| `PostgresStore` | several app servers | conformance suite against a **fake driver** locally; **real Postgres in CI** (`stores.yml`) |
| `RedisStore` | several app servers | real Redis in CI only |

## What the suite enforces
roundtrip of JSON values and hostile keys (SQL metacharacters, unicode, 500 chars) - copy-in/copy-out semantics (no aliasing) - TTL expiry,
TTL replaced by `set`, TTL *kept* (not extended) by `update` - create-if-absent - `undefined` = no change, `null` = delete -
a throwing callback rolls back and leaves the store usable - **150 concurrent increments lose nothing** - **60 concurrent
create-if-absent calls have exactly one winner** - concurrent set/del/update never corrupt a key.

## Postgres design
`src/storage/postgres-store.js` takes any `pg`-compatible pool (the driver is *not* a dependency).
Every write is `BEGIN` -> `pg_advisory_xact_lock(hashtextextended(key, 0))` -> work -> `COMMIT`.
Why an advisory lock rather than `SELECT ... FOR UPDATE`? Row locks cannot protect a row that does not exist yet, which is exactly the
"first failed attempt creates the counter" race. The lock is per key, so different users never contend. Keys, values and TTLs are always bound
parameters; the only interpolated identifier (the table name) is validated against `[A-Za-z_][A-Za-z0-9_]{0,62}`.
Needs PostgreSQL >= 11. Run `store.sweep()` from a timer to delete expired rows.
```bash
npm install pg
OTP_DATABASE_URL=postgres://user:pass@host:5432/otp node bin/server.js
```
## Running the real-database conformance locally
```bash
docker compose -f deploy/docker-compose.test-stores.yml up -d
npm i --no-save pg ioredis
PG_URL=postgres://otpf:otpf@127.0.0.1:55432/otpf REDIS_URL=redis://127.0.0.1:56379 npm run test:stores
```
## Writing your own store
Implement `get / set / del / update`, call `storeConformance('MyStore', factory)` from a test, and do not ship until it is green - including the
two concurrency tests, which are the ones naive implementations fail.

## Operational notes
* **TTL and clocks:** expiry is evaluated in the application with the injected clock, so skew between app servers matters - run NTP. Expired rows are deleted lazily on read and by `store.sweep()`.
* **Pool sizing:** every `update` holds one connection for one short transaction.
* **Production safety:** `bin/server.js` refuses to start in production without `OTP_DATABASE_URL`, `OTP_SQLITE_FILE` or `OTP_STORE_FILE` (override: `OTP_ALLOW_MEMORY_STORE=1`), because a volatile store silently loses enrolments, lockouts and replay guards on restart.
* **What the suite already caught:** `MemoryStore` returned live object references, so a caller mutating a result silently changed stored state.
