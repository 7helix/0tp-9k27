// "Scan a QR with your logged-in phone to sign in on the computer" (like WhatsApp Web).
//  browser: create() -> shows QR (payload) and polls claim() with its private pollToken
//  phone:   approve() -> already-authenticated app confirms the session for its user
// The pollToken never appears in the QR, so someone who photographs the QR can't claim the session.
import { randomBytes, b64url, sha256hex, safeEqual } from '../core/crypto-utils.js';

export class QrLogin {
  constructor({ store, clock = Date.now, scheme = 'otpf://qr-login' }) { Object.assign(this, { store, clock, scheme }); }
  #k = (sid) => `qr:${sid}`;

  async create({ ttlMs = 120_000, meta = {} } = {}) {
    const sessionId = b64url(randomBytes(16)), nonce = b64url(randomBytes(16)), pollToken = b64url(randomBytes(32));
    await this.store.set(this.#k(sessionId), {
      nonce, pollHash: sha256hex(pollToken), status: 'pending', userId: null, meta, expiresAt: this.clock() + ttlMs,
    }, ttlMs);
    return { sessionId, pollToken, qrPayload: `${this.scheme}?sid=${sessionId}&n=${nonce}` };
  }
  /** Called by the authenticated mobile app after the user confirms "Sign in on <meta.device>?" */
  async approve({ sessionId, nonce, userId }) {
    let out = { ok: false, reason: 'unknown_or_expired' };
    await this.store.update(this.#k(sessionId), (r) => {
      if (!r || r.expiresAt <= this.clock()) return undefined;
      if (!safeEqual(r.nonce, nonce)) { out = { ok: false, reason: 'bad_nonce' }; return undefined; }
      if (r.status !== 'pending') { out = { ok: false, reason: r.status }; return undefined; }
      out = { ok: true, meta: r.meta };
      return { ...r, status: 'approved', userId };
    });
    return out;
  }
  /** Called by the browser while polling; succeeds exactly once. */
  async claim({ sessionId, pollToken }) {
    let out = { ok: false, status: 'pending' };
    await this.store.update(this.#k(sessionId), (r) => {
      if (!r || r.expiresAt <= this.clock()) { out = { ok: false, status: 'expired' }; return undefined; }
      if (!safeEqual(r.pollHash, sha256hex(String(pollToken)))) { out = { ok: false, status: 'forbidden' }; return undefined; }
      if (r.status !== 'approved') { out = { ok: false, status: r.status }; return undefined; }
      out = { ok: true, userId: r.userId };
      return { ...r, status: 'claimed' };
    });
    return out;
  }
}
