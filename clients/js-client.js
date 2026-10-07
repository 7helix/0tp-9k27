// Small fetch-based client for the HTTP API.
//
// Returns the parsed body for 200 and 429 (rate limited), and throws OtpApiError for anything else
// (400, 401, 404, 413, 5xx). Authenticate with either `apiKey`, or `hmac: { keyId, secret }` to sign
// each request.
import { signRequest } from '../src/http/signed-requests.js';

export class OtpApiError extends Error {
  constructor(status, body) {
    super(body?.error || `HTTP ${status}`);
    this.status = status;
    this.body = body;
  }
}

export class OtpFortressClient {
  constructor({ baseUrl, apiKey, hmac, fetchImpl = fetch, timeoutMs = 5000 }) {
    this.baseUrl = baseUrl.replace(/\/$/, '');
    this.apiKey = apiKey;
    this.hmac = hmac;
    this.fetchImpl = fetchImpl;
    this.timeoutMs = timeoutMs;
  }

  async #post(path, body) {
    const payload = JSON.stringify(body);

    const auth = this.hmac
      ? signRequest({ method: 'POST', path, body: payload, keyId: this.hmac.keyId, secret: this.hmac.secret })
      : { 'x-api-key': this.apiKey };

    const response = await this.fetchImpl(this.baseUrl + path, {
      method: 'POST',
      headers: { 'content-type': 'application/json', ...auth },
      body: payload,
      signal: AbortSignal.timeout(this.timeoutMs),
    });

    const json = await response.json().catch(() => ({}));
    if (response.status === 200 || response.status === 429) return json;
    throw new OtpApiError(response.status, json);
  }

  sendOtp(userId, channel, to) {
    return this.#post('/otp/send', { userId, channel, to });
  }

  verifyOtp(userId, code) {
    return this.#post('/otp/verify', { userId, code });
  }

  enrollTotp(userId, account) {
    return this.#post('/totp/enroll', { userId, account });
  }

  confirmTotp(userId, code) {
    return this.#post('/totp/confirm', { userId, code });
  }

  verifyTotp(userId, code) {
    return this.#post('/totp/verify', { userId, code });
  }

  generateBackupCodes(userId) {
    return this.#post('/backup/generate', { userId });
  }

  verifyBackupCode(userId, code) {
    return this.#post('/backup/verify', { userId, code });
  }
}
