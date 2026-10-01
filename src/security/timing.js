// Uniform response time blunts timing side-channels and account enumeration ("unknown user" fast path).
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
export async function withMinDuration(minMs, fn, { jitterMs = 0 } = {}) {
  if (!minMs) return fn();
  const wait = minMs + (jitterMs ? Math.random() * jitterMs : 0);
  const [result] = await Promise.allSettled([fn(), sleep(wait)]);
  if (result.status === 'rejected') throw result.reason;
  return result.value;
}
