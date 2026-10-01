# Python port
Stdlib-only HOTP/TOTP (+ verify with window & replay protection), verified against the same RFC vectors as the JS core.
```bash
cd ports/python && python3 -m unittest -v
```
Roadmap: port the OTP-type modules (challenge OTP, backup codes, transaction OTP). PRs welcome.
