// Require a CAPTCHA only after suspicious volume (keeps normal users friction-free).
// SiteverifyCaptcha works with Cloudflare Turnstile, hCaptcha and reCAPTCHA-style "siteverify" APIs.
export class SiteverifyCaptcha {
  constructor({ url, secret, fetchImpl = fetch }) { Object.assign(this, { url, secret, fetchImpl }); }
  async verify(token, ip) {
    if (!token) return false;
    const body = new URLSearchParams({ secret: this.secret, response: token });
    if (ip) body.set('remoteip', ip);
    const r = await this.fetchImpl(this.url, { method: 'POST', body });
    return r.ok && (await r.json()).success === true;
  }
}
export const TURNSTILE_URL = 'https://challenges.cloudflare.com/turnstile/v0/siteverify';
export const HCAPTCHA_URL = 'https://hcaptcha.com/siteverify';
export const RECAPTCHA_URL = 'https://www.google.com/recaptcha/api/siteverify';

export class CaptchaGate {
  constructor({ store, verifier, freeRequests = 2, windowMs = 3_600_000, clock = Date.now }) { Object.assign(this, { store, verifier, freeRequests, windowMs, clock }); }
  /** Returns { allowed, captchaRequired }. Counts every call; captcha needed beyond the free quota. */
  async check({ key, captchaToken, ip }) {
    const rec = await this.store.update(`captcha:${key}`, (c) => ({ n: (c?.n || 0) + 1 }), this.windowMs);
    if (rec.n <= this.freeRequests) return { allowed: true, captchaRequired: false };
    const ok = await this.verifier.verify(captchaToken, ip);
    return { allowed: ok, captchaRequired: true };
  }
}
