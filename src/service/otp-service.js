// The orchestrator: combines every building block into one hardened API.
import { randomBytes, hkdf, wipe } from '../core/crypto-utils.js';
import { base32Encode } from '../core/base32.js';
import { encrypt, decrypt } from '../core/secret-box.js';
import { buildOtpauthUri } from '../core/otpauth.js';
import { totp, verifyTotp } from '../core/totp.js';
import { normalizeNumericInput } from '../core/format.js';
import { ChallengeOtp } from '../otp-types/challenge-otp.js';
import { MagicLink } from '../otp-types/magic-link.js';
import { BackupCodes } from '../otp-types/backup-codes.js';
import { TransactionOtp } from '../otp-types/transaction-otp.js';
import { PushApproval } from '../otp-types/push-approval.js';
import { SlidingWindowLimiter } from '../security/rate-limiter.js';
import { LockoutPolicy } from '../security/lockout.js';
import { AuditLog } from '../security/audit-log.js';
import { smsText, emailContent } from '../delivery/templates.js';
import { maskDestination } from '../delivery/providers.js';

export class OtpService {
  constructor({ store, masterKey, pepper, provider, audit = new AuditLog(), anomaly = null, brand = 'MyApp', domain = 'example.com', baseUrl = 'https://example.com', clock = Date.now }) {
    if (!Buffer.isBuffer(masterKey) || masterKey.length !== 32) throw new Error('masterKey must be a 32-byte Buffer');
    Object.assign(this, { store, masterKey, provider, audit, anomaly, brand, domain, clock });
    this.challenge = new ChallengeOtp({ store, pepper, clock });
    this.magic = new MagicLink({ store, pepper, baseUrl, clock });
    this.backup = new BackupCodes({ store });
    this.txn = new TransactionOtp({ store, masterKey, clock });
    this.push = new PushApproval({ store, clock });
    this.issueLimiter = new SlidingWindowLimiter({ store, limit: 3, windowMs: 600_000, clock, name: 'issue' });
    this.verifyLimiter = new SlidingWindowLimiter({ store, limit: 10, windowMs: 600_000, clock, name: 'verify' });
    this.lockout = new LockoutPolicy({ store, clock });
    this.totpKey = hkdf(masterKey, 'totp-seed-encryption');
  }

  // ---------- Email / SMS OTP ----------
  async sendOtp({ userId, channel, to, purpose = 'login', ip }) {
    const rl = await this.issueLimiter.hit(`${userId}:${channel}`);
    if (!rl.allowed) { this.audit.append('otp.issue.rate_limited', { userId, channel, ip }); return { ok: false, reason: 'rate_limited', retryAfterMs: rl.retryAfterMs }; }
    const { code, expiresAt } = await this.challenge.issue({ userId, purpose });
    const message = channel === 'sms'
      ? { text: smsText({ code, brand: this.brand, domain: this.domain }) }
      : emailContent({ code, brand: this.brand });
    await this.provider.send({ channel, to, message });
    this.audit.append('otp.issued', { userId, channel, to: maskDestination(to), purpose, ip });
    return { ok: true, sentTo: maskDestination(to), expiresAt };
  }
  async verifyOtp({ userId, code, purpose = 'login', ip }) {
    const gate = await this.#gate(userId, 'otp', ip);
    if (gate) return gate;
    const r = await this.challenge.verify({ userId, purpose, code });
    return this.#finish(userId, 'otp', r, ip);
  }

  // ---------- TOTP (authenticator apps) ----------
  async enrollTotp({ userId, account, algorithm = 'SHA1', digits = 6, period = 30 }) {
    const secret = randomBytes(20);
    const rec = { enc: encrypt(this.totpKey, secret, userId), algorithm, digits, period, confirmed: false, lastCounter: -1 };
    await this.store.set(`totp:${userId}`, rec);
    const base32 = base32Encode(secret);
    wipe(secret);
    this.audit.append('totp.enroll_started', { userId });
    return { secret: base32, uri: buildOtpauthUri({ issuer: this.brand, account, secret: base32, algorithm, digits, period }) };
  }
  async #totpVerify(userId, rawCode, { confirming, ip }) {
    const gate = await this.#gate(userId, 'totp', ip);
    if (gate) return gate;
    const rec = await this.store.get(`totp:${userId}`);
    if (!rec || (rec.confirmed === confirming)) return { ok: false, reason: confirming ? 'nothing_to_confirm' : 'not_enrolled' };
    const code = normalizeNumericInput(rawCode);
    const secret = decrypt(this.totpKey, rec.enc, userId);
    let res;
    try { res = verifyTotp(secret, code, { time: this.clock(), step: rec.period, digits: rec.digits, algorithm: rec.algorithm, lastUsedCounter: rec.lastCounter }); }
    finally { wipe(secret); }
    if (res.valid) {
      // Atomic replay guard: only one request can advance lastCounter to this value.
      let advanced = false;
      await this.store.update(`totp:${userId}`, (cur) => {
        if (cur.lastCounter >= res.counter) return undefined;
        advanced = true; return { ...cur, lastCounter: res.counter, confirmed: true };
      });
      if (!advanced) return this.#finish(userId, 'totp', { ok: false, reason: 'replayed' }, ip);
      return this.#finish(userId, 'totp', { ok: true }, ip);
    }
    return this.#finish(userId, 'totp', { ok: false, reason: res.reason }, ip);
  }
  confirmTotp({ userId, code, ip }) { return this.#totpVerify(userId, code, { confirming: true, ip }); }
  verifyTotpCode({ userId, code, ip }) { return this.#totpVerify(userId, code, { confirming: false, ip }); }
  /** For tests/demos only. */
  async _currentTotp(userId) {
    const rec = await this.store.get(`totp:${userId}`);
    const secret = decrypt(this.totpKey, rec.enc, userId);
    try { return totp(secret, { time: this.clock(), step: rec.period, digits: rec.digits, algorithm: rec.algorithm }); } finally { wipe(secret); }
  }

  // ---------- Backup codes ----------
  async generateBackupCodes(userId) { this.audit.append('backup.generated', { userId }); return this.backup.generate(userId); }
  async useBackupCode({ userId, code, ip }) {
    const gate = await this.#gate(userId, 'backup', ip);
    if (gate) return gate;
    const r = await this.backup.consume(userId, code);
    return this.#finish(userId, 'backup', r.ok ? { ok: true, remaining: r.remaining } : { ok: false, reason: 'invalid' }, ip);
  }

  // ---------- shared guard: anomaly + rate limit + lockout, and result bookkeeping ----------
  async #gate(userId, kind, ip) {
    if (this.anomaly && ip && await this.anomaly.isSuspicious(ip)) {
      this.audit.append('verify.suspicious_ip', { userId, kind, ip });
      return { ok: false, reason: 'suspicious_ip' };
    }
    const lock = await this.lockout.status(`${kind}:${userId}`);
    if (lock.locked) { this.audit.append('verify.locked_out', { userId, kind, ip }); return { ok: false, reason: 'locked', retryAfterMs: lock.retryAfterMs }; }
    const rl = await this.verifyLimiter.hit(`${kind}:${userId}`);
    if (!rl.allowed) return { ok: false, reason: 'rate_limited', retryAfterMs: rl.retryAfterMs };
    return null;
  }
  async #finish(userId, kind, result, ip) {
    if (result.ok) { await this.lockout.reset(`${kind}:${userId}`); this.audit.append('verify.success', { userId, kind, ip }); }
    else if (!['no_active_code', 'not_enrolled', 'nothing_to_confirm'].includes(result.reason)) {
      await this.lockout.recordFailure(`${kind}:${userId}`);
      if (this.anomaly && ip) await this.anomaly.recordFailure({ ip, userId });
      this.audit.append('verify.failure', { userId, kind, reason: result.reason, ip });
    }
    return result;
  }
}
