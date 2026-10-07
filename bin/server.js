#!/usr/bin/env node
import {
  loadConfig,
  OtpService,
  createServer,
  MemoryStore,
  FileStore,
  PostgresStore,
  AuditLog,
  ConsoleProvider,
  AnomalyDetector,
  Metrics,
  WebAuthn,
} from '../src/index.js';

const config = loadConfig();

async function openStore() {
  if (config.databaseUrl) {
    let pg;
    try {
      pg = (await import('pg')).default;
    } catch {
      throw new Error('OTP_DATABASE_URL needs the Postgres driver: run `npm install pg` (it is not a dependency of this repo on purpose)');
    }
    const pool = new pg.Pool({ connectionString: config.databaseUrl });
    const store = new PostgresStore({ pool });
    await store.init();
    return { store, label: 'postgres', close: () => pool.end() };
  }

  if (config.sqliteFile) {
    const { SqliteStore } = await import('../src/storage/sqlite-store.js'); // needs Node 22.5+
    const store = new SqliteStore(config.sqliteFile);
    const sweeper = setInterval(() => store.sweep(), 60_000);
    sweeper.unref();
    return { store, label: `sqlite:${config.sqliteFile}`, close: async () => store.close() };
  }

  if (config.storeFile) {
    return { store: new FileStore(config.storeFile), label: `file:${config.storeFile}`, close: async () => {} };
  }

  console.warn('[warn] using the in-memory store: enrolments, lockouts and replay guards are lost on restart');
  return { store: new MemoryStore(), label: 'memory', close: async () => {} };
}

const { store, label, close } = await openStore();

const service = new OtpService({
  store,
  masterKey: config.masterKey,
  pepper: config.pepper,
  provider: new ConsoleProvider(), // swap for a real provider (see src/delivery)
  audit: new AuditLog({ filePath: config.auditFile }),
  anomaly: new AnomalyDetector({ store }),
});

const server = createServer(service, {
  apiKey: config.apiKey,
  hmac: config.hmacKeys ? { keys: config.hmacKeys, store } : null,
  allowedCidrs: config.allowedCidrs,
  trustedProxies: config.trustedProxies,
  minVerifyMs: config.minVerifyMs,
  uniformErrors: config.uniformErrors,
  metrics: config.metrics ? new Metrics() : null,
  webauthn: config.webauthn ? new WebAuthn({ store, ...config.webauthn }) : null,
});

function describeWebauthn() {
  if (!config.webauthn) return 'off';
  const { formats, requireTrustedChain, aaguidAllowlist } = config.webauthn.attestation;
  const trusted = requireTrustedChain || aaguidAllowlist ? ', trusted chain required' : '';
  return `on (attestation: ${formats.join('+')}${trusted})`;
}

server.listen(config.port, () => {
  const auth = config.hmacKeys ? `HMAC (${Object.keys(config.hmacKeys).length} key id(s))` : 'static API key';
  const allowlist = config.allowedCidrs ? config.allowedCidrs.join(',') : 'off';

  console.log(`0TP-F0rtr3ss listening on :${server.address().port}`);
  console.log(
    `auth: ${auth} | store: ${label} | allowlist: ${allowlist} | webauthn: ${describeWebauthn()} | metrics: ${config.metrics ? 'on' : 'off'}`,
  );
  if (config.apiKey && !process.env.OTP_API_KEY) console.log(`Dev API key: ${config.apiKey}`);
});

for (const signal of ['SIGINT', 'SIGTERM']) {
  process.on(signal, () => {
    server.close(async () => {
      await close();
      process.exit(0);
    });
  });
}
