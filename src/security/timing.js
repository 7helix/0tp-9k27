// Makes every response take at least `minMs`, so a fast "no such user" path can't be told apart from
// a slower "wrong code" path by timing.
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

export async function withMinDuration(minMs, fn, { jitterMs = 0 } = {}) {
  if (!minMs) return fn();

  const wait = minMs + (jitterMs ? Math.random() * jitterMs : 0);
  const [result] = await Promise.allSettled([fn(), sleep(wait)]);
  if (result.status === 'rejected') throw result.reason;
  return result.value;
}
