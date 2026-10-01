# ADR 0005 - HMAC-signed requests instead of only a static API key
**Status:** accepted. **Context:** a bearer key is replayable and leaks through logs. **Decision:** offer signed requests (method, path, timestamp, nonce, body hash) as a first-class auth mode; keep the static key for simple setups.
Nonces are claimed only after the signature verifies. **Consequences:** needs synchronized clocks and a shared atomic nonce store; callers need a small signing helper (provided for JS and Python).
