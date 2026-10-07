# Contributing
1. Fork, branch, `npm test` must stay green (zero runtime dependencies is a hard rule).
2. New OTP type = one file in `src/otp-types/`, tests in `tests/`, a section in `docs/02-otp-types.md`.
3. Never log or return secrets/codes outside the one place a user must see them.
4. Use `node:crypto` only. No home-made primitives. Compare secrets with `safeEqual`.
5. Add a threat-model line for anything that changes trust boundaries.

## Style
- Keep lines under about 110 characters and one statement per line.
- Comments explain why something is done, not what the next line does. Skip banners and shouting.
- Prefer small named helpers over long one-liners, and plain names over clever ones.
- No new runtime dependencies. Anything that touches secrets goes through `src/core`.

