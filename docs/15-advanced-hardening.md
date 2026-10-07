# Advanced hardening: the defence stack

| Layer | Module | Turn it on with |
|---|---|---|
| Network allowlist | `http/cidr.js` | `createServer(svc, { allowedCidrs: ['10.0.0.0/8'] })` |
| Trusted proxies / real client IP | `clientIp()` | `trustedProxies: ['10.0.0.0/8']` (never trust `X-Forwarded-For` otherwise) |
| Caller authentication | `http/signed-requests.js` | `hmac: { keys: { 'backend-1': secret }, store }` |
| Anti-enumeration | `uniformErrors` | default on; `'strict'` also hides "not enrolled" |
| Timing side-channels | `security/timing.js` | `minVerifyMs: 150` |
| Credential stuffing | `AnomalyDetector` | `new OtpService({ anomaly })` |
| Abuse cost control | `ProofOfWork`, `CaptchaGate` | in front of `/otp/send` |
| Impossible travel | `security/geo.js` | feed `assessRisk({ impossibleTravel })` |
| Master-key custody | `security/shamir.js` | split into N shares, K to reconstruct |
| Key rotation | `KeyRing` | see `docs/12-key-rotation.md` |
| Tamper-evident logs | `AuditLog` + `AuditCheckpointer` + `bin/audit-tool.js` | sign checkpoints off-box |
| Metrics / alerting | `http/metrics.js` | `metrics: new Metrics()` -> scrape `/metrics` |
| Phishing-proof factor | `webauthn/` | `webauthn: new WebAuthn({...})` |

## A fully hardened server
```js
import { OtpService, createServer, Metrics, AnomalyDetector, MemoryStore, WebAuthn, randomBytes } from './src/index.js';
const store = new MemoryStore();                          // swap for SqliteStore / your atomic store
const svc = new OtpService({ store, masterKey, pepper, provider, audit, anomaly: new AnomalyDetector({ store }) });
createServer(svc, {
  hmac: { keys: { 'backend-1': process.env.BACKEND_1_SECRET_BUFFER }, store },
  allowedCidrs: ['10.0.0.0/8'], trustedProxies: ['10.0.0.0/8'],
  minVerifyMs: 150, uniformErrors: 'strict', metrics: new Metrics(),
  webauthn: new WebAuthn({ store, rpId: 'example.com', origins: ['https://example.com'] }),
}).listen(8080);
```
## Operational rules that code cannot enforce
1. Checkpoint the audit log to a host the OTP server cannot write to. 2. Alert on spikes of `locked`, `suspicious_ip`,
`rate_limited` in `/metrics`. 3. Rotate HMAC caller secrets by adding a second key id, migrating callers, deleting the first.
4. Never log request bodies. 5. Practise the master-key recovery ceremony before you need it.
