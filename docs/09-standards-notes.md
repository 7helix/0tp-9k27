# Standards & regulation notes (orientation, not legal advice)
Always read the current text of each standard - versions change.

| Source | Relevance |
|---|---|
| RFC 4226 (HOTP) | counters, truncation, resync procedure, >=128-bit secrets |
| RFC 6238 (TOTP) | time steps, allowing limited drift, hash choices |
| RFC 6287 (OCRA) | challenge-response; this repo implements an OCRA-*inspired* simplification |
| RFC 6238 / Key URI Format (Google Authenticator wiki) | `otpauth://` provisioning URIs |
| NIST SP 800-63B | authenticator assurance levels; treats SMS/voice OTP as a "restricted" authenticator; guidance on OTP lifetimes and throttling |
| PSD2 SCA (EU) | "dynamic linking" of authentication to amount and payee - the idea behind `TransactionOtp` |
| WebOTP / origin-bound SMS | `@domain #code` last line so browsers autofill only on the right site |
| OWASP ASVS / Cheat Sheets | verification requirements for MFA, rate limiting, secure storage |

Privacy: phone numbers and emails are personal data - minimise retention, mask in logs (`maskDestination`), and delete audit data on your retention schedule.
