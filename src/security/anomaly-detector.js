// Spots credential-stuffing / enumeration: ONE ip failing against MANY different accounts.
// (Per-account lockouts cannot see this pattern - each account has only a single failure.)
export class AnomalyDetector {
  constructor({ store, distinctUsers = 8, windowMs = 600_000, clock = Date.now }) { Object.assign(this, { store, distinctUsers, windowMs, clock }); }
  async recordFailure({ ip, userId }) {
    const now = this.clock();
    return this.store.update(`anom:${ip}`, (cur) => {
      const events = (cur?.events || []).filter((e) => e.t > now - this.windowMs);
      events.push({ t: now, u: userId });
      return { events };
    }, this.windowMs);
  }
  async isSuspicious(ip) {
    const rec = await this.store.get(`anom:${ip}`);
    if (!rec) return false;
    const now = this.clock();
    return new Set(rec.events.filter((e) => e.t > now - this.windowMs).map((e) => e.u)).size >= this.distinctUsers;
  }
}
