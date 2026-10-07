// The HTTP API. Plain node:http, no framework.
//
// Every route needs authentication: either a static x-api-key header or HMAC-signed requests.
// Optional extras: IP allowlist, response-time padding, uniform error messages, /metrics, and the
// WebAuthn routes. Put it behind TLS and only let your own backend reach it.
import http from 'node:http';
import { safeEqual } from '../core/crypto-utils.js';
import { isUserId, isOtpCode, validateDestination } from '../security/input-validation.js';
import { withMinDuration } from '../security/timing.js';
import { verifyRequest } from './signed-requests.js';
import { clientIp, matchesAny, parseCidr } from './cidr.js';

const MAX_BODY = 10 * 1024;

// "wrong code", "no code" and "expired code" look the same from the outside by default
const GENERIC_REASONS = new Set(['no_active_code', 'expired', 'invalid']);
const STRICT_REASONS = new Set(['not_enrolled', 'nothing_to_confirm']);

function httpError(status, message) {
  return Object.assign(new Error(message), { status });
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    let tooBig = false;

    req.on('data', (chunk) => {
      size += chunk.length;
      if (tooBig) return; // keep draining so the client gets our 413, but store nothing
      if (size > MAX_BODY) {
        tooBig = true;
        reject(httpError(413, 'too_large'));
      } else {
        chunks.push(chunk);
      }
    });
    req.on('end', () => {
      if (!tooBig) resolve(Buffer.concat(chunks));
    });
    req.on('error', reject);
  });
}

function parseJsonObject(raw) {
  if (raw.length === 0) return {};
  try {
    const value = JSON.parse(raw);
    if (value === null || typeof value !== 'object' || Array.isArray(value)) throw new Error('not an object');
    return value;
  } catch {
    throw httpError(400, 'bad_json');
  }
}

// Checks the fields a route needs. Throws a 400 on the first problem.
function requireFields(body, ...names) {
  for (const name of names) {
    if (typeof body[name] !== 'string' || !body[name]) throw httpError(400, `missing_${name}`);
  }
  if (names.includes('userId') && !isUserId(body.userId)) throw httpError(400, 'invalid_userId');
  if (names.includes('code') && !isOtpCode(body.code)) throw httpError(400, 'invalid_code');
  if (names.includes('to')) validateDestination(body.channel, body.to);
}

function maskReason(result, mode) {
  if (!mode || result?.ok !== false) return result;
  const generic = GENERIC_REASONS.has(result.reason);
  const strict = mode === 'strict' && STRICT_REASONS.has(result.reason);
  return generic || strict ? { ok: false, reason: 'invalid_or_expired' } : result;
}

export function createServer(service, options = {}) {
  const {
    apiKey,
    hmac = null,
    allowedCidrs = null,
    trustedProxies = [],
    metrics = null,
    webauthn = null,
    minVerifyMs = 0,
    uniformErrors = true,
  } = options;

  if (!apiKey && !hmac) throw new Error('configure `apiKey` or `hmac` authentication');

  const allowlist = allowedCidrs ? allowedCidrs.map(parseCidr) : null;
  const proxies = trustedProxies.map(parseCidr);

  // `verify: true` marks routes that check a secret. Those get uniform errors and optional padding.
  const routes = {
    'POST /otp/send': {
      run: (body, ip) => {
        requireFields(body, 'userId', 'channel', 'to');
        return service.sendOtp({ ...body, ip });
      },
    },
    'POST /otp/verify': {
      verify: true,
      run: (body, ip) => {
        requireFields(body, 'userId', 'code');
        return service.verifyOtp({ ...body, ip });
      },
    },
    'POST /totp/enroll': {
      run: (body) => {
        requireFields(body, 'userId', 'account');
        return service.enrollTotp(body);
      },
    },
    'POST /totp/confirm': {
      verify: true,
      run: (body, ip) => {
        requireFields(body, 'userId', 'code');
        return service.confirmTotp({ ...body, ip });
      },
    },
    'POST /totp/verify': {
      verify: true,
      run: (body, ip) => {
        requireFields(body, 'userId', 'code');
        return service.verifyTotpCode({ ...body, ip });
      },
    },
    'POST /backup/generate': {
      run: async (body) => {
        requireFields(body, 'userId');
        return { codes: await service.generateBackupCodes(body.userId) };
      },
    },
    'POST /backup/verify': {
      verify: true,
      run: (body, ip) => {
        requireFields(body, 'userId', 'code');
        return service.useBackupCode({ ...body, ip });
      },
    },
    'GET /health': {
      public: true,
      run: async () => ({ ok: true }),
    },
  };

  if (metrics) {
    routes['GET /metrics'] = { text: true, run: async () => metrics.render() };
  }

  if (webauthn) {
    const needResponse = (body) => {
      if (!body.response || typeof body.response !== 'object') throw httpError(400, 'missing_response');
    };
    routes['POST /webauthn/register/start'] = {
      run: (body) => {
        requireFields(body, 'userId', 'userName');
        return webauthn.startRegistration(body);
      },
    };
    routes['POST /webauthn/register/finish'] = {
      run: (body) => {
        requireFields(body, 'userId');
        needResponse(body);
        return webauthn.finishRegistration(body);
      },
    };
    routes['POST /webauthn/auth/start'] = {
      run: (body) => {
        requireFields(body, 'userId');
        return webauthn.startAuthentication(body);
      },
    };
    routes['POST /webauthn/auth/finish'] = {
      verify: true,
      run: (body) => {
        requireFields(body, 'userId');
        needResponse(body);
        return webauthn.finishAuthentication(body);
      },
    };
  }

  return http.createServer(async (req, res) => {
    let routeLabel = 'unknown'; // only known routes become metric labels, so scanners can't blow up cardinality

    const send = (status, body, { text = false } = {}) => {
      metrics?.inc('otpf_http_requests_total', { route: routeLabel, status }, 1, 'HTTP requests handled');
      res.writeHead(status, {
        'content-type': text ? 'text/plain; version=0.0.4' : 'application/json',
        'cache-control': 'no-store',
        'x-content-type-options': 'nosniff',
        'referrer-policy': 'no-referrer',
        ...(status === 413 ? { connection: 'close' } : {}),
      });
      res.end(text ? body : JSON.stringify(body));
    };

    try {
      const path = (req.url || '').split('?')[0];
      const route = routes[`${req.method} ${path}`];
      if (!route) return send(404, { error: 'not_found' });
      routeLabel = path;

      const ip = clientIp(req, proxies);
      if (allowlist && !matchesAny(ip, allowlist)) return send(403, { error: 'forbidden' });

      let raw = Buffer.alloc(0);
      if (!route.public) {
        if (hmac) {
          if (!req.headers['x-otpf-signature']) return send(401, { error: 'unauthorized' });
          if (req.method === 'POST') raw = await readBody(req);
          const verified = await verifyRequest({
            method: req.method,
            path,
            body: raw,
            headers: req.headers,
            keys: hmac.keys,
            store: hmac.store,
            skewMs: hmac.skewMs,
          });
          if (!verified.ok) return send(401, { error: 'unauthorized' });
        } else {
          if (!safeEqual(req.headers['x-api-key'] || '', apiKey)) return send(401, { error: 'unauthorized' });
          if (req.method === 'POST') raw = await readBody(req);
        }
      }

      const body = req.method === 'POST' ? parseJsonObject(raw) : {};
      const run = () => route.run(body, ip);
      let result = route.verify && minVerifyMs ? await withMinDuration(minVerifyMs, run) : await run();

      if (route.text) return send(200, result, { text: true });

      if (route.verify) {
        result = maskReason(result, uniformErrors);
        const outcome = result?.ok ? 'ok' : (result?.reason ?? 'error');
        metrics?.inc('otpf_verify_total', { route: path, result: outcome }, 1, 'Verification outcomes');
      }

      const rateLimited = result?.ok === false && result.reason === 'rate_limited';
      send(rateLimited ? 429 : 200, result);
    } catch (err) {
      if (err.status) return send(err.status, { error: err.message });
      console.error(err);
      send(500, { error: 'internal_error' }); // never leak internals
    }
  });
}
