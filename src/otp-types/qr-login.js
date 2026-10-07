// Sign in on a computer by scanning a QR code with a phone that is already logged in (like WhatsApp Web).
//   browser: create() shows the QR and polls claim() using a private pollToken
//   phone:   approve() confirms the session for the logged-in user
// The pollToken is never in the QR code, so somebody who photographs the QR can't claim the session.
import { randomBytes, b64url, sha256hex, safeEqual } from '../core/crypto-utils.js';

export class QrLogin {
  constructor({ store, clock = Date.now, scheme = 'otpf://qr-login' }) {
    this.store = store;
    this.clock = clock;
    this.scheme = scheme;
  }

  #key(sessionId) {
    return `qr:${sessionId}`;
  }

  async create({ ttlMs = 120_000, meta = {} } = {}) {
    const sessionId = b64url(randomBytes(16));
    const nonce = b64url(randomBytes(16));
    const pollToken = b64url(randomBytes(32));

    await this.store.set(this.#key(sessionId), {
      nonce,
      pollHash: sha256hex(pollToken), // only the hash is kept
      status: 'pending',
      userId: null,
      meta,
      expiresAt: this.clock() + ttlMs,
    }, ttlMs);

    return { sessionId, pollToken, qrPayload: `${this.scheme}?sid=${sessionId}&n=${nonce}` };
  }

  // Called by the phone app once the user confirms "Sign in on <device>?"
  async approve({ sessionId, nonce, userId }) {
    let outcome = { ok: false, reason: 'unknown_or_expired' };

    await this.store.update(this.#key(sessionId), (session) => {
      if (!session || session.expiresAt <= this.clock()) return undefined;
      if (!safeEqual(session.nonce, nonce)) {
        outcome = { ok: false, reason: 'bad_nonce' };
        return undefined;
      }
      if (session.status !== 'pending') {
        outcome = { ok: false, reason: session.status };
        return undefined;
      }
      outcome = { ok: true, meta: session.meta };
      return { ...session, status: 'approved', userId };
    });

    return outcome;
  }

  // Called by the browser while it polls. Succeeds once.
  async claim({ sessionId, pollToken }) {
    let outcome = { ok: false, status: 'pending' };

    await this.store.update(this.#key(sessionId), (session) => {
      if (!session || session.expiresAt <= this.clock()) {
        outcome = { ok: false, status: 'expired' };
        return undefined;
      }
      if (!safeEqual(session.pollHash, sha256hex(String(pollToken)))) {
        outcome = { ok: false, status: 'forbidden' };
        return undefined;
      }
      if (session.status !== 'approved') {
        outcome = { ok: false, status: session.status };
        return undefined;
      }
      outcome = { ok: true, userId: session.userId };
      return { ...session, status: 'claimed' };
    });

    return outcome;
  }
}
