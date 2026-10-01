// Learns a user's device clock drift. If the last N successful codes all landed in the same
// non-zero time-step, suggest an offset so verification can centre the window on that device.
export class DriftTracker {
  constructor({ samples = 3, maxOffset = 2 } = {}) { Object.assign(this, { samples, maxOffset }); this.map = new Map(); }
  record(userId, delta) {
    const list = [...(this.map.get(userId) || []), delta].slice(-this.samples);
    this.map.set(userId, list);
  }
  /** Integer number of steps to add to `now` when verifying this user, or 0. */
  suggestedOffset(userId) {
    const l = this.map.get(userId) || [];
    if (l.length < this.samples) return 0;
    const [first] = l;
    if (first === 0 || Math.abs(first) > this.maxOffset || !l.every((d) => d === first)) return 0;
    return first;
  }
}
// NOTE: verifyTotp() reports `delta` = (matched counter - current counter). A steady delta of -1 means
// the phone's clock is one step BEHIND the server; verify that user with time + offset * step * 1000.
