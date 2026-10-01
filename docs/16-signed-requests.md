# HMAC-signed requests

A static `x-api-key` leaks via logs, proxies and memory dumps, and anyone who sees one request can replay it forever.
Signed requests fix that: the secret never travels, the body is covered, and each request is single-use.

## Specification
```
canonical = METHOD + "\n" + PATH + "\n" + TIMESTAMP_MS + "\n" + NONCE + "\n" + hex(SHA-256(BODY))
signature = base64url( HMAC-SHA-256(secret, canonical) )          (no padding)

headers:  x-otpf-key-id | x-otpf-timestamp | x-otpf-nonce (8-64 chars [A-Za-z0-9_-]) | x-otpf-signature
```
Server checks, in this order: headers well-formed -> key id known (constant-time even if not) -> timestamp within +/-60 s ->
signature equal (constant time) -> **then** claims the nonce (so forged requests cannot burn real nonces) -> replay = reject.
Every failure is a bare `401 unauthorized`; the real reason is deliberately not disclosed.

## Clients
```js
import { OtpFortressClient } from './clients/js-client.js';
new OtpFortressClient({ baseUrl, hmac: { keyId: 'backend-1', secret } });
```
```python
from otp_fortress_client import OtpFortressClient
OtpFortressClient(base_url, hmac_key_id="backend-1", hmac_secret=secret_bytes)
```
Both are tested against the same server (`tests/cli-hmac.test.js`), so the canonical form is byte-compatible.

## Limits
Signing authenticates the *caller*, it does not encrypt - keep TLS. Clock skew beyond 60 s needs NTP. The nonce store must be shared
(and atomic) across server instances. Sign `path` without the query string; do not use query parameters on these routes.
