// Remembers how far off a user's phone clock is. If the last few good codes all landed in the same
// non-zero time step, we suggest an offset so their window can be centred on their device.
//
// verifyTotp() reports delta = matched counter - current counter. A steady -1 means the phone is one
// step behind the server, so verify that user with time + offset * step * 1000.
export class DriftTracker {
  constructor({ samples = 3, maxOffset = 2 } = {}) {
    this.samples = samples;
    this.maxOffset = maxOffset;
    this.history = new Map();
  }

  record(userId, delta) {
    const recent = [...(this.history.get(userId) || []), delta].slice(-this.samples);
    this.history.set(userId, recent);
  }

  // Whole steps to add to the clock for this user, or 0.
  suggestedOffset(userId) {
    const recent = this.history.get(userId) || [];
    if (recent.length < this.samples) return 0;

    const [first] = recent;
    const steady = recent.every((delta) => delta === first);
    if (!steady || first === 0 || Math.abs(first) > this.maxOffset) return 0;
    return first;
  }
}
