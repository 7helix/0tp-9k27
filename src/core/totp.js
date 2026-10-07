// TOTP, RFC 6238: HOTP where the counter is the current time divided into 30 second steps.
import { hotp } from './hotp.js';
import { safeEqual } from './crypto-utils.js';

export function totpCounter(timeMs = Date.now(), step = 30, t0 = 0) {
  return Math.floor((Math.floor(timeMs / 1000) - t0) / step);
}

export function totp(secret, { time = Date.now(), step = 30, digits = 6, algorithm = 'SHA1', t0 = 0 } = {}) {
  return hotp(secret, totpCounter(time, step, t0), { digits, algorithm });
}

// Checks a code allowing for clock drift (`window` steps either side) and refuses replays:
// pass the last counter you accepted as `lastUsedCounter`, and store the `counter` we return.
export function verifyTotp(secret, code, options = {}) {
  const {
    time = Date.now(),
    step = 30,
    digits = 6,
    algorithm = 'SHA1',
    t0 = 0,
    window = 1,
    lastUsedCounter = -1,
  } = options;

  const current = totpCounter(time, step, t0);
  let match = null;
  let replayed = false;

  // `0 - window` rather than `-window`, so a window of 0 gives 0 and not -0
  for (let delta = 0 - window; delta <= window; delta++) {
    const counter = current + delta;
    const candidate = hotp(secret, counter, { digits, algorithm });
    if (safeEqual(candidate, String(code)) && !match) {
      if (counter <= lastUsedCounter) replayed = true;
      else match = { counter, delta };
    }
  }

  if (match) return { valid: true, ...match };
  return { valid: false, reason: replayed ? 'replayed' : 'invalid' };
}
