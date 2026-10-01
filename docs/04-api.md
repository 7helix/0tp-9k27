# HTTP API (all routes except /health need header `x-api-key`)

| Method & path | Body | Success response |
|---|---|---|
| POST /otp/send | `{userId, channel:"sms"|"email", to}` | `{ok, sentTo(masked), expiresAt}` or 429 `rate_limited` |
| POST /otp/verify | `{userId, code}` | `{ok:true}` / `{ok:false, reason, attemptsLeft?}` |
| POST /totp/enroll | `{userId, account}` | `{secret, uri}` (show QR once) |
| POST /totp/confirm | `{userId, code}` | `{ok}` |
| POST /totp/verify | `{userId, code}` | `{ok}` / `{ok:false, reason:"invalid|replayed|locked|rate_limited"}` |
| POST /backup/generate | `{userId}` | `{codes:[...]}` (only time they are visible) |
| POST /backup/verify | `{userId, code}` | `{ok, remaining}` |
| GET /health | - | `{ok:true}` |

Reasons you may see: `no_active_code, expired, too_many_attempts, invalid, replayed, locked, rate_limited, not_enrolled`.
Errors: 400 validation, 401 bad key, 404, 413 body too large, 429 rate limited, 500 generic.

## Hardened-mode additions
- Auth: either `x-api-key` **or** signed requests (`x-otpf-*` headers, see [16](16-signed-requests.md)). Failures are always a bare `401`.
- `403 forbidden` - caller IP is outside `OTP_ALLOWED_CIDRS`.
- Verify routes return `invalid_or_expired` (unknown / expired / wrong) by default; `suspicious_ip`, `locked`, `rate_limited`, `too_many_attempts` stay explicit.
- `GET /metrics` (authenticated, only when enabled) - Prometheus text format.
- WebAuthn (only when enabled): `POST /webauthn/register/start|finish`, `POST /webauthn/auth/start|finish` with `{ userId, ... }` / `{ userId, response }`; see [14](14-webauthn-passkeys.md).
