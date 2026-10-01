# OTP types in this repo

| # | Type | File | Use it for | Phishing resistance | Notes |
|---|------|------|-----------|---------------------|-------|
| 1 | HOTP (RFC 4226) | core/hotp.js | hardware tokens, offline devices | low | counter + look-ahead resync |
| 2 | TOTP (RFC 6238) | core/totp.js | authenticator apps | low-medium | drift window + replay guard |
| 3 | Email OTP | otp-types/challenge-otp.js | verify email, low-risk 2FA | low | random, hashed, 5 attempts |
| 4 | SMS OTP | same + delivery/templates.js | reach everyone | low | origin-bound `@domain #code` format |
| 5 | Voice OTP | otp-types/voice-otp.js | landlines, accessibility | low | TTS script generator |
| 6 | Alphanumeric OTP | challenge-otp.js (`kind:'alnum'`) | manual entry, longer codes | low | unambiguous alphabet |
| 7 | Magic link | otp-types/magic-link.js | passwordless login | medium | 256-bit, single use |
| 8 | Backup codes | otp-types/backup-codes.js | account recovery | n/a | 10 x ~50-bit, scrypt |
| 9 | Transaction OTP | otp-types/transaction-otp.js | payments, sensitive actions | **high** | code bound to amount+payee |
| 10 | Push + number matching | otp-types/push-approval.js | app-based approval | medium-high | defeats MFA fatigue |
| 11 | Challenge-response | otp-types/challenge-response.js | tokens, kiosks | medium | fresh challenge each time |
| 12 | Signed step-up token | otp-types/signed-token.js | "OTP passed, continue" sessions | n/a | HMAC, fixed alg, expiring |

**Ranking advice:** passkeys/WebAuthn > push with number matching > TOTP > email > SMS.
Use OTPs as a strong second factor, and offer better factors when you can.
