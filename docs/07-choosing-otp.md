# Which OTP should I use?

```
Need to authorise a payment / irreversible action?  -> Transaction OTP (bound to amount+payee) or passkey
Need 2FA for everyday login?
  users have smartphones + you can ship an app?     -> Push with number matching
  no app, but users can install any authenticator?  -> TOTP (+ backup codes!)
  must reach users with only a phone number?        -> SMS (fallback only) + rate limits + origin-bound format
  landline / accessibility?                         -> Voice OTP
Passwordless sign-in by email?                      -> Magic link (single use, short TTL)
Sign in on a desktop using the phone you already trust? -> QR login
Hardware tokens?                                    -> HOTP devices (with resync)
"Remember me on this device"?                       -> Device trust (revocable)
User lost their second factor?                      -> Backup codes, then delayed recovery request
```

## Trade-off table
| | Setup friction | Phishing-resistant | Works offline | Cost per login |
|--|--|--|--|--|
| Passkey / WebAuthn | low | **yes** | yes | 0 |
| Push + number matching | medium | partly | no | ~0 |
| TOTP | medium | no | yes | 0 |
| Email OTP | none | no | no | ~0 |
| SMS OTP | none | no (SIM swap, SS7) | no | **$0.01-0.10+** |

Rule of thumb: offer the strongest factor you can, keep weaker ones as fallbacks, and never let a weak fallback silently
undo a strong factor (attackers just pick "use SMS instead").
