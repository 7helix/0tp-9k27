// Dependency-free HTTP API. Defence in depth, all optional except authentication:
//  * auth:        static `x-api-key`  OR  HMAC-signed requests (body-bound, replay-protected)
//  * network:     CIDR allowlist + safe client-IP extraction behind trusted proxies
//  * anti-abuse:  uniform error responses (anti-enumeration), response-time padding
//  * observability: Prometheus /metrics (authenticated)
//  * optional WebAuthn/passkey routes
// Put it behind TLS and a network policy; never expose it directly to browsers.
import http from 'node:http';
import { safeEqual } from '../core/crypto-utils.js';
import { isUserId, isOtpCode, validateDestination } from '../security/input-validation.js';
import { withMinDuration } from '../security/timing.js';
import { verifyRequest } from './signed-requests.js';
import { clientIp, matchesAny, parseCidr } from './cidr.js';

const MAX_BODY = 10 * 1024;
const GENERIC = new Set(['no_active_code', 'expired', 'invalid']);
const STRICT = new Set(['not_enrolled', 'nothing_to_confirm']);

function readRaw(req) {
  return new Promise((resolve, reject) => {
    let size = 0, tooBig = false; const chunks = [];
    req.on('data', (c) => {
      size += c.length;
      if (tooBig) return;                       // keep draining, store nothing
      if (size > MAX_BODY) { tooBig = true; reject(Object.assign(new Error('too_large'), { status: 413 })); }
      else chunks.push(c);
    });
    req.on('end', () => { if (!tooBig) resolve(Buffer.concat(chunks)); });
    req.on('error', reject);
  });
}
const parseJson = (raw) => {
  if (!raw.length) return {};
  try {
    const v = JSON.parse(raw);
    if (v === null || typeof v !== 'object' || Array.isArray(v)) throw new Error();
    return v;
  } catch { throw Object.assign(new Error('bad_json'), { status: 400 }); }
};
const bad = (msg) => Object.assign(new Error(msg), { status: 400 });
const need = (b, ...f) => {
  for (const k of f) if (typeof b[k] !== 'string' || !b[k]) throw bad(`missing_${k}`);
  if (f.includes('userId') && !isUserId(b.userId)) throw bad('invalid_userId');
  if (f.includes('code') && !isOtpCode(b.code)) throw bad('invalid_code');
  if (f.includes('to')) validateDestination(b.channel, b.to);
};
const uniform = (result, mode) => {
  if (!mode || result?.ok !== false) return result;
  if (GENERIC.has(result.reason) || (mode === 'strict' && STRICT.has(result.reason))) return { ok: false, reason: 'invalid_or_expired' };
  return result;
};

export function createServer(service, { apiKey, hmac = null, allowedCidrs = null, trustedProxies = [], metrics = null, webauthn = null, minVerifyMs = 0, uniformErrors = true } = {}) {
  if (!apiKey && !hmac) throw new Error('configure `apiKey` or `hmac` authentication');
  const allow = allowedCidrs ? allowedCidrs.map(parseCidr) : null;
  const trusted = trustedProxies.map(parseCidr);
  const obj = (b) => b && typeof b === 'object';

  const routes = {
    'POST /otp/send':        { fn: (b, ip) => { need(b, 'userId', 'channel', 'to'); return service.sendOtp({ ...b, ip }); } },
    'POST /otp/verify':      { verify: true, fn: (b, ip) => { need(b, 'userId', 'code'); return service.verifyOtp({ ...b, ip }); } },
    'POST /totp/enroll':     { fn: (b) => { need(b, 'userId', 'account'); return service.enrollTotp(b); } },
    'POST /totp/confirm':    { verify: true, fn: (b, ip) => { need(b, 'userId', 'code'); return service.confirmTotp({ ...b, ip }); } },
    'POST /totp/verify':     { verify: true, fn: (b, ip) => { need(b, 'userId', 'code'); return service.verifyTotpCode({ ...b, ip }); } },
    'POST /backup/generate': { fn: async (b) => { need(b, 'userId'); return { codes: await service.generateBackupCodes(b.userId) }; } },
    'POST /backup/verify':   { verify: true, fn: (b, ip) => { need(b, 'userId', 'code'); return service.useBackupCode({ ...b, ip }); } },
    'GET /health':           { public: true, fn: async () => ({ ok: true }) },
  };
  if (metrics) routes['GET /metrics'] = { text: true, fn: async () => metrics.render() };
  if (webauthn) {
    routes['POST /webauthn/register/start']  = { fn: (b) => { need(b, 'userId', 'userName'); return webauthn.startRegistration(b); } };
    routes['POST /webauthn/register/finish'] = { fn: (b) => { need(b, 'userId'); if (!obj(b.response)) throw bad('missing_response'); return webauthn.finishRegistration(b); } };
    routes['POST /webauthn/auth/start']      = { fn: (b) => { need(b, 'userId'); return webauthn.startAuthentication(b); } };
    routes['POST /webauthn/auth/finish']     = { verify: true, fn: (b) => { need(b, 'userId'); if (!obj(b.response)) throw bad('missing_response'); return webauthn.finishAuthentication(b); } };
  }

  return http.createServer(async (req, res) => {
    let routeLabel = 'unknown';
    const send = (status, body, { text = false } = {}) => {
      metrics?.inc('otpf_http_requests_total', { route: routeLabel, status }, 1, 'HTTP requests handled');
      res.writeHead(status, {
        'content-type': text ? 'text/plain; version=0.0.4' : 'application/json', 'cache-control': 'no-store',
        'x-content-type-options': 'nosniff', 'referrer-policy': 'no-referrer',
        ...(status === 413 ? { connection: 'close' } : {}),
      });
      res.end(text ? body : JSON.stringify(body));
    };
    try {
      const path = (req.url || '').split('?')[0];
      const route = routes[`${req.method} ${path}`];
      if (!route) return send(404, { error: 'not_found' });
      routeLabel = path;
      const ip = clientIp(req, trusted);
      if (allow && !matchesAny(ip, allow)) return send(403, { error: 'forbidden' });

      let raw = Buffer.alloc(0);
      if (!route.public) {
        if (hmac) {
          if (!req.headers['x-otpf-signature']) return send(401, { error: 'unauthorized' });
          if (req.method === 'POST') raw = await readRaw(req);
          const v = await verifyRequest({ method: req.method, path, body: raw, headers: req.headers, keys: hmac.keys, store: hmac.store, skewMs: hmac.skewMs });
          if (!v.ok) return send(401, { error: 'unauthorized' });
        } else {
          if (!safeEqual(req.headers['x-api-key'] || '', apiKey)) return send(401, { error: 'unauthorized' });
          if (req.method === 'POST') raw = await readRaw(req);
        }
      }
      const body = req.method === 'POST' ? parseJson(raw) : {};
      const run = () => route.fn(body, ip);
      let result = route.verify && minVerifyMs ? await withMinDuration(minVerifyMs, run) : await run();
      if (route.text) return send(200, result, { text: true });
      if (route.verify) {
        result = uniform(result, uniformErrors);
        metrics?.inc('otpf_verify_total', { route: path, result: result?.ok ? 'ok' : (result?.reason ?? 'error') }, 1, 'Verification outcomes');
      }
      send(result?.ok === false && result.reason === 'rate_limited' ? 429 : 200, result);
    } catch (e) {
      if (e.status) return send(e.status, { error: e.message });
      console.error(e); send(500, { error: 'internal_error' }); // never leak internals
    }
  });
}
