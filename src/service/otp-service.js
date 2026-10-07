// Ties the building blocks together: email/SMS codes, TOTP, backup codes, and the checks that
// every verification goes through (anomaly check, lockout, rate limit, audit log).
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

// A wrong guess against these says nothing about the user, so it doesn't count towards a lockout.
const NOT_A_FAILURE = ['no_active_code', 'not_enrolled', 'nothing_to_confirm'];

export class OtpService {
  constructor({
    store,
    masterKey,
    pepper,
    provider,
    audit = new AuditLog(),
    anomaly = null,
    brand = 'MyApp',
    domain = 'example.com',
    baseUrl = 'https://example.com',
    clock = Date.now,
  }) {
    if (!Buffer.isBuffer(masterKey) || masterKey.length !== 32) {
      throw new Error('masterKey must be a 32-byte Buffer');
    }

    this.store = store;
    this.masterKey = masterKey;
    this.provider = provider;
    this.audit = audit;
    this.anomaly = anomaly;
    this.brand = brand;
    this.domain = domain;
    this.clock = clock;

    this.challenge = new ChallengeOtp({ store, pepper, clock });
    this.magic = new MagicLink({ store, pepper, baseUrl, clock });
    this.backup = new BackupCodes({ store });
    this.txn = new TransactionOtp({ store, masterKey, clock });
    this.push = new PushApproval({ store, clock });

    // 3 codes per 10 minutes per user and channel, 10 verification tries per 10 minutes
    this.issueLimiter = new SlidingWindowLimiter({ store, limit: 3, windowMs: 600_000, clock, name: 'issue' });
    this.verifyLimiter = new SlidingWindowLimiter({ store, limit: 10, windowMs: 600_000, clock, name: 'verify' });
    this.lockout = new LockoutPolicy({ store, clock });

    this.totpKey = hkdf(masterKey, 'totp-seed-encryption');
  }

  // ---- email / SMS codes ----

  async sendOtp({ userId, channel, to, purpose = 'login', ip }) {
    const limit = await this.issueLimiter.hit(`${userId}:${channel}`);
    if (!limit.allowed) {
      this.audit.append('otp.issue.rate_limited', { userId, channel, ip });
      return { ok: false, reason: 'rate_limited', retryAfterMs: limit.retryAfterMs };
    }

    const { code, expiresAt } = await this.challenge.issue({ userId, purpose });
    const message = channel === 'sms'
      ? { text: smsText({ code, brand: this.brand, domain: this.domain }) }
      : emailContent({ code, brand: this.brand });
    await this.provider.send({ channel, to, message });

    this.audit.append('otp.issued', { userId, channel, to: maskDestination(to), purpose, ip });
    return { ok: true, sentTo: maskDestination(to), expiresAt };
  }

  async verifyOtp({ userId, code, purpose = 'login', ip }) {
    const blocked = await this.#gate(userId, 'otp', ip);
    if (blocked) return blocked;

    const result = await this.challenge.verify({ userId, purpose, code });
    return this.#finish(userId, 'otp', result, ip);
  }

  // ---- TOTP (authenticator apps) ----

  async enrollTotp({ userId, account, algorithm = 'SHA1', digits = 6, period = 30 }) {
    const secret = randomBytes(20);
    const record = {
      enc: encrypt(this.totpKey, secret, userId),
      algorithm,
      digits,
      period,
      confirmed: false,
      lastCounter: -1,
    };
    await this.store.set(`totp:${userId}`, record);

    const base32 = base32Encode(secret);
    wipe(secret);

    this.audit.append('totp.enroll_started', { userId });
    const uri = buildOtpauthUri({ issuer: this.brand, account, secret: base32, algorithm, digits, period });
    return { secret: base32, uri };
  }

  confirmTotp({ userId, code, ip }) {
    return this.#checkTotp(userId, code, { confirming: true, ip });
  }

  verifyTotpCode({ userId, code, ip }) {
    return this.#checkTotp(userId, code, { confirming: false, ip });
  }

  async #checkTotp(userId, rawCode, { confirming, ip }) {
    const blocked = await this.#gate(userId, 'totp', ip);
    if (blocked) return blocked;

    // confirming only makes sense for an enrolment that isn't confirmed yet, and the reverse for logins
    const record = await this.store.get(`totp:${userId}`);
    if (!record || record.confirmed === confirming) {
      return { ok: false, reason: confirming ? 'nothing_to_confirm' : 'not_enrolled' };
    }

    const code = normalizeNumericInput(rawCode);
    const secret = decrypt(this.totpKey, record.enc, userId);
    let check;
    try {
      check = verifyTotp(secret, code, {
        time: this.clock(),
        step: record.period,
        digits: record.digits,
        algorithm: record.algorithm,
        lastUsedCounter: record.lastCounter,
      });
    } finally {
      wipe(secret);
    }

    if (!check.valid) {
      return this.#finish(userId, 'totp', { ok: false, reason: check.reason }, ip);
    }

    // Remember the counter we just used. Doing it inside update() means two parallel requests with
    // the same code can't both get through: only one of them moves lastCounter forward.
    let advanced = false;
    await this.store.update(`totp:${userId}`, (current) => {
      if (current.lastCounter >= check.counter) return undefined;
      advanced = true;
      return { ...current, lastCounter: check.counter, confirmed: true };
    });

    const result = advanced ? { ok: true } : { ok: false, reason: 'replayed' };
    return this.#finish(userId, 'totp', result, ip);
  }

  // test helper: what the user's authenticator app would show right now
  async _currentTotp(userId) {
    const record = await this.store.get(`totp:${userId}`);
    const secret = decrypt(this.totpKey, record.enc, userId);
    try {
      return totp(secret, {
        time: this.clock(),
        step: record.period,
        digits: record.digits,
        algorithm: record.algorithm,
      });
    } finally {
      wipe(secret);
    }
  }

  // ---- backup codes ----

  async generateBackupCodes(userId) {
    this.audit.append('backup.generated', { userId });
    return this.backup.generate(userId);
  }

  async useBackupCode({ userId, code, ip }) {
    const blocked = await this.#gate(userId, 'backup', ip);
    if (blocked) return blocked;

    const used = await this.backup.consume(userId, code);
    const result = used.ok ? { ok: true, remaining: used.remaining } : { ok: false, reason: 'invalid' };
    return this.#finish(userId, 'backup', result, ip);
  }

  // ---- checks shared by every verification ----

  // Returns a rejection if this attempt shouldn't even be looked at, otherwise null.
  async #gate(userId, kind, ip) {
    if (this.anomaly && ip && await this.anomaly.isSuspicious(ip)) {
      this.audit.append('verify.suspicious_ip', { userId, kind, ip });
      return { ok: false, reason: 'suspicious_ip' };
    }

    const lock = await this.lockout.status(`${kind}:${userId}`);
    if (lock.locked) {
      this.audit.append('verify.locked_out', { userId, kind, ip });
      return { ok: false, reason: 'locked', retryAfterMs: lock.retryAfterMs };
    }

    const limit = await this.verifyLimiter.hit(`${kind}:${userId}`);
    if (!limit.allowed) {
      return { ok: false, reason: 'rate_limited', retryAfterMs: limit.retryAfterMs };
    }
    return null;
  }

  // Bookkeeping after an attempt: reset the lockout on success, count and log failures.
  async #finish(userId, kind, result, ip) {
    if (result.ok) {
      await this.lockout.reset(`${kind}:${userId}`);
      this.audit.append('verify.success', { userId, kind, ip });
      return result;
    }

    if (!NOT_A_FAILURE.includes(result.reason)) {
      await this.lockout.recordFailure(`${kind}:${userId}`);
      if (this.anomaly && ip) await this.anomaly.recordFailure({ ip, userId });
      this.audit.append('verify.failure', { userId, kind, reason: result.reason, ip });
    }
    return result;
  }
}
