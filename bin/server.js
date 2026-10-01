#!/usr/bin/env node
import {
  loadConfig, OtpService, createServer, MemoryStore, FileStore, AuditLog, ConsoleProvider, AnomalyDetector, Metrics, WebAuthn,
} from '../src/index.js';

const cfg = loadConfig();
const store = cfg.storeFile ? new FileStore(cfg.storeFile) : new MemoryStore();
const audit = new AuditLog({ filePath: cfg.auditFile });
const service = new OtpService({
  store, masterKey: cfg.masterKey, pepper: cfg.pepper, provider: new ConsoleProvider(), audit,
  anomaly: new AnomalyDetector({ store }),
});
const server = createServer(service, {
  apiKey: cfg.apiKey, hmac: cfg.hmacKeys ? { keys: cfg.hmacKeys, store } : null,
  allowedCidrs: cfg.allowedCidrs, trustedProxies: cfg.trustedProxies, minVerifyMs: cfg.minVerifyMs,
  uniformErrors: cfg.uniformErrors, metrics: cfg.metrics ? new Metrics() : null,
  webauthn: cfg.webauthn ? new WebAuthn({ store, ...cfg.webauthn }) : null,
});
server.listen(cfg.port, () => {
  console.log(`0TP-F0rtr3ss listening on :${server.address().port}`);
  console.log(`auth: ${cfg.hmacKeys ? `HMAC (${Object.keys(cfg.hmacKeys).length} key id(s))` : 'static API key'} | allowlist: ${cfg.allowedCidrs ? cfg.allowedCidrs.join(',') : 'off'} | webauthn: ${cfg.webauthn ? 'on' : 'off'} | metrics: ${cfg.metrics ? 'on' : 'off'}`);
  if (cfg.apiKey && !process.env.OTP_API_KEY) console.log(`Dev API key: ${cfg.apiKey}`);
});
for (const sig of ['SIGINT', 'SIGTERM']) process.on(sig, () => server.close(() => process.exit(0)));
