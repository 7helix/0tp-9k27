# Java port
Single file, no dependencies, Java 17+ (uses records and switch expressions).
```bash
java ports/java/OtpFortress.java selftest       # RFC 4226/6238 vectors + verify/replay/base32 -> "OK ..."
echo "totp GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ 59000 8 SHA1" | java ports/java/OtpFortress.java batch
```
Use it in a project by copying `OtpFortress.java` into your source tree (it has no package declaration; add yours).
API: `hotp`, `totp`, `verifyTotp` (window + replay counter), `safeEqual`, `base32Encode/Decode`.
Verified here: all RFC vectors and cross-language agreement with the Node core (`scripts/cross-check.js`).
