import { signRequest } from '../src/http/signed-requests.js';

// Tiny fetch-based SDK for the HTTP API. Returns the parsed body for 200 and 429 (rate limited);
// throws OtpApiError for everything else (400/401/404/413/5xx).
export class OtpApiError extends Error {
  constructor(status, body) { super(body?.error || `HTTP ${status}`); this.status = status; this.body = body; }
}
export class OtpFortressClient {
  // Auth: pass `apiKey` (static header) OR `hmac: { keyId, secret }` (signed, replay-protected requests).
  constructor({ baseUrl, apiKey, hmac, fetchImpl = fetch, timeoutMs = 5000 }) { Object.assign(this, { baseUrl: baseUrl.replace(/\/$/, ''), apiKey, hmac, fetchImpl, timeoutMs }); }
  async #post(path, body) {
    const payload = JSON.stringify(body);
    const auth = this.hmac ? signRequest({ method: 'POST', path, body: payload, keyId: this.hmac.keyId, secret: this.hmac.secret }) : { 'x-api-key': this.apiKey };
    const r = await this.fetchImpl(this.baseUrl + path, {
      method: 'POST', headers: { 'content-type': 'application/json', ...auth },
      body: payload, signal: AbortSignal.timeout(this.timeoutMs),
    });
    const json = await r.json().catch(() => ({}));
    if (r.status === 200 || r.status === 429) return json;
    throw new OtpApiError(r.status, json);
  }
  sendOtp(userId, channel, to) { return this.#post('/otp/send', { userId, channel, to }); }
  verifyOtp(userId, code) { return this.#post('/otp/verify', { userId, code }); }
  enrollTotp(userId, account) { return this.#post('/totp/enroll', { userId, account }); }
  confirmTotp(userId, code) { return this.#post('/totp/confirm', { userId, code }); }
  verifyTotp(userId, code) { return this.#post('/totp/verify', { userId, code }); }
  generateBackupCodes(userId) { return this.#post('/backup/generate', { userId }); }
  verifyBackupCode(userId, code) { return this.#post('/backup/verify', { userId, code }); }
}
