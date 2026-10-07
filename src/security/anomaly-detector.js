// Spots credential stuffing: one IP failing against many different accounts. Per-account lockouts
// can't see it, because each account only has a single failure.
export class AnomalyDetector {
  constructor({ store, distinctUsers = 8, windowMs = 600_000, clock = Date.now }) {
    this.store = store;
    this.distinctUsers = distinctUsers;
    this.windowMs = windowMs;
    this.clock = clock;
  }

  async recordFailure({ ip, userId }) {
    const now = this.clock();
    return this.store.update(`anom:${ip}`, (record) => {
      const events = (record?.events || []).filter((event) => event.t > now - this.windowMs);
      events.push({ t: now, u: userId });
      return { events };
    }, this.windowMs);
  }

  async isSuspicious(ip) {
    const record = await this.store.get(`anom:${ip}`);
    if (!record) return false;

    const since = this.clock() - this.windowMs;
    const users = new Set(record.events.filter((event) => event.t > since).map((event) => event.u));
    return users.size >= this.distinctUsers;
  }
}
