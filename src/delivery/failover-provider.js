// Try providers in order; skip a provider for `cooldownMs` after `maxFailures` consecutive failures
// (a tiny circuit breaker). One SMS gateway outage must not lock every user out.
export class FailoverProvider {
  constructor(providers, { maxFailures = 3, cooldownMs = 60_000, clock = Date.now } = {}) {
    this.list = providers.map((p) => ({ p, fails: 0, until: 0 }));
    Object.assign(this, { maxFailures, cooldownMs, clock });
  }
  async send(msg) {
    const errors = [];
    for (const s of this.list) {
      if (s.until > this.clock()) continue;
      try {
        const r = await s.p.send(msg);
        s.fails = 0;
        return { ...r, via: s.p.constructor.name };
      } catch (e) {
        errors.push(e.message);
        if (++s.fails >= this.maxFailures) { s.until = this.clock() + this.cooldownMs; s.fails = 0; }
      }
    }
    throw new Error(`All providers failed: ${errors.join(' | ') || 'all in cooldown'}`);
  }
}
