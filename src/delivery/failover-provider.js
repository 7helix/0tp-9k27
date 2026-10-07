// Tries providers in order. A provider that fails `maxFailures` times in a row is skipped for
// `cooldownMs` (a small circuit breaker), so one SMS gateway outage doesn't lock everyone out.
export class FailoverProvider {
  constructor(providers, { maxFailures = 3, cooldownMs = 60_000, clock = Date.now } = {}) {
    this.slots = providers.map((provider) => ({ provider, failures: 0, skipUntil: 0 }));
    this.maxFailures = maxFailures;
    this.cooldownMs = cooldownMs;
    this.clock = clock;
  }

  async send(message) {
    const errors = [];

    for (const slot of this.slots) {
      if (slot.skipUntil > this.clock()) continue;

      try {
        const result = await slot.provider.send(message);
        slot.failures = 0;
        return { ...result, via: slot.provider.constructor.name };
      } catch (err) {
        errors.push(err.message);
        slot.failures += 1;
        if (slot.failures >= this.maxFailures) {
          slot.skipUntil = this.clock() + this.cooldownMs;
          slot.failures = 0;
        }
      }
    }

    throw new Error(`All providers failed: ${errors.join(' | ') || 'all in cooldown'}`);
  }
}
