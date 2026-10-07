# Python port
Stdlib-only HOTP/TOTP (+ verify with window & replay protection), verified against the same RFC vectors as the JS core.
```bash
cd ports/python && python3 -m unittest -v
```
Also: `python3 otp_fortress.py batch` (used by `scripts/cross-check.js`).
Roadmap: port the OTP-type modules (challenge OTP, backup codes, transaction OTP). PRs welcome.
