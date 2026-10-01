// Sliding-window rate limiter. Use it on BOTH issuing OTPs (stops SMS-bombing / cost abuse)
// and verifying OTPs (stops brute force).
export class SlidingWindowLimiter {
  constructor({ store, limit, windowMs, clock = Date.now, name = 'rl' }) {
    Object.assign(this, { store, limit, windowMs, clock, name });
  }
  async hit(id) {
    const now = this.clock();
    let result;
    await this.store.update(`${this.name}:${id}`, (cur) => {
      const hits = (cur || []).filter((t) => t > now - this.windowMs);
      if (hits.length >= this.limit) {
        result = { allowed: false, remaining: 0, retryAfterMs: hits[0] + this.windowMs - now };
        return hits.length === (cur || []).length ? undefined : hits;
      }
      hits.push(now);
      result = { allowed: true, remaining: this.limit - hits.length, retryAfterMs: 0 };
      return hits;
    }, this.windowMs);
    return result;
  }
}
