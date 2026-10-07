# Red-team playbook: attacks, expected outcome, and the test that proves it

| # | Attack | Expected | Test |
|---|---|---|---|
| 1 | Sequential brute force of a 6-digit code | never succeeds; budget exhausted; real code then dead | `RED TEAM: sequential brute force...` |
| 2 | 60 parallel guesses over HTTP | <= 5 real comparisons happen | `...parallel guess storm...` |
| 3 | Reuse A's code for user B / other purpose | rejected | `...useless for user B...` |
| 4 | Replay one TOTP code in parallel | exactly 1 success | `...parallel replay of one valid TOTP...` |
| 5 | Double-spend a backup code | exactly 1 success | `...backup-code double spend...` |
| 6 | Read DB/log for secrets | none in plaintext, destinations masked | `...nothing sensitive is stored...` |
| 7 | Steal DB, copy ciphertext between users / other key | decrypt fails | `...stolen DB alone...` |
| 8 | Path/method confusion, dot-segments, `;`, `%00`, `%2F` | 404 | `...HTTP surface...` |
| 9 | Key-guessing variants, header/query auth smuggling | 401 | `...HTTP surface...` |
| 10 | `__proto__` / `constructor` pollution | no effect | `...HTTP surface...`, `fuzz: HTTP API...` |
| 11 | Oversized / non-object JSON bodies | 413 / 400 | `...HTTP surface...` |
| 12 | Account enumeration via verify responses | identical bodies | `uniform errors...` |
| 13 | Timing oracle on verify | padded responses (`minVerifyMs`) | `response-time padding...` |
| 14 | Credential stuffing from one IP; spoofed `ip` / `X-Forwarded-For` | IP cut off; spoofing ignored | `credential-stuffing IP...`, `IP allowlist...` |
| 15 | Replayed / tampered / stale signed request | 401 | `signed requests...`, `HMAC-signed mode...` |
| 16 | Phishing origin, wrong rpId, replayed or cloned passkey | rejected with specific reason | `WebAuthn registration/authentication attacks` |
| 17 | Tamper with or truncate the audit log | detected offline | `audit-tool...`, `audit checkpoints...` |
| 18 | Random garbage into every parser | clean errors, no 500, no hang | `fuzz:*` (seeded: `FUZZ_SEED=123 npm test`) |

## Manual tests no suite replaces
Run a real browser + security key through `/webauthn/*`; load-test the verify path with the limiter on; port-scan the deployed host;
try the API from a disallowed network; restore from backup and rehearse master-key recovery; have someone who did not write this code review `src/security/` and `src/webauthn/`.
