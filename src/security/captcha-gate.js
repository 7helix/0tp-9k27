// Ask for a CAPTCHA only after unusual volume, so normal users never see one.
// SiteverifyCaptcha talks to the "siteverify" style API that Turnstile, hCaptcha and reCAPTCHA share.
export const TURNSTILE_URL = 'https://challenges.cloudflare.com/turnstile/v0/siteverify';
export const HCAPTCHA_URL = 'https://hcaptcha.com/siteverify';
export const RECAPTCHA_URL = 'https://www.google.com/recaptcha/api/siteverify';

export class SiteverifyCaptcha {
  constructor({ url, secret, fetchImpl = fetch }) {
    this.url = url;
    this.secret = secret;
    this.fetchImpl = fetchImpl;
  }

  async verify(token, ip) {
    if (!token) return false;

    const body = new URLSearchParams({ secret: this.secret, response: token });
    if (ip) body.set('remoteip', ip);

    const response = await this.fetchImpl(this.url, { method: 'POST', body });
    return response.ok && (await response.json()).success === true;
  }
}

export class CaptchaGate {
  constructor({ store, verifier, freeRequests = 2, windowMs = 3_600_000, clock = Date.now }) {
    this.store = store;
    this.verifier = verifier;
    this.freeRequests = freeRequests;
    this.windowMs = windowMs;
    this.clock = clock;
  }

  // Every call counts. Once `freeRequests` is used up, a valid CAPTCHA token is required.
  async check({ key, captchaToken, ip }) {
    const record = await this.store.update(`captcha:${key}`, (current) => ({ n: (current?.n || 0) + 1 }), this.windowMs);
    if (record.n <= this.freeRequests) return { allowed: true, captchaRequired: false };

    const passed = await this.verifier.verify(captchaToken, ip);
    return { allowed: passed, captchaRequired: true };
  }
}
