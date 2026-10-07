// Sliding window rate limiter. Use it when issuing codes (stops SMS bombing and cost abuse) and
// when verifying them (stops brute force).
export class SlidingWindowLimiter {
  constructor({ store, limit, windowMs, clock = Date.now, name = 'rl' }) {
    this.store = store;
    this.limit = limit;
    this.windowMs = windowMs;
    this.clock = clock;
    this.name = name;
  }

  async hit(id) {
    const now = this.clock();
    let result;

    await this.store.update(`${this.name}:${id}`, (previous) => {
      const before = previous || [];
      const recent = before.filter((time) => time > now - this.windowMs);

      if (recent.length >= this.limit) {
        result = { allowed: false, remaining: 0, retryAfterMs: recent[0] + this.windowMs - now };
        // nothing to write unless old hits dropped out of the window
        return recent.length === before.length ? undefined : recent;
      }

      recent.push(now);
      result = { allowed: true, remaining: this.limit - recent.length, retryAfterMs: 0 };
      return recent;
    }, this.windowMs);

    return result;
  }
}
