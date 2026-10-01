# FAQ
**Why are email/SMS codes hashed if they expire in 5 minutes?** A DB/log leak during that window would otherwise hand out live codes.
**Why HMAC+pepper and not bcrypt for them?** See `docs/adr/0003-hmac-not-bcrypt.md`.
**Can I use this with Google Authenticator / Authy / 1Password?** Yes: SHA1, 6 digits, 30 s (the defaults). SHA256/512 are supported by some apps but ignored by others.
**Is TOTP phishable?** Yes - a real-time proxy can relay the code. Use passkeys where possible.
**Why does `verify` count an attempt before comparing?** So parallel guesses can't race past the limit.
**Why is the API key required on every route?** The service is meant to be called by *your backend*, not browsers.
**Can two servers share the file store?** No. Use SQLite on one host, or write a Redis/SQL store with an atomic `update`.
**What if a user's phone clock is wrong?** +/-1 step is tolerated; `DriftTracker` can suggest a per-user offset.
**How do I rotate keys?** `docs/12-key-rotation.md`.
**Is it production-ready?** It is carefully tested and documented but unaudited - see SECURITY.md.
