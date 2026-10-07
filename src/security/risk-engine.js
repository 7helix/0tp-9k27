// Decides how much proof to ask for, from signals you already have. The weights are a starting
// point: tune them against your own data.
export function assessRisk({
  newDevice = false,
  ipChanged = false,
  impossibleTravel = false,
  recentFailures = 0,
  highValue = false,
  offHours = false,
} = {}) {
  let score = 0;
  if (newDevice) score += 30;
  if (ipChanged) score += 10;
  if (impossibleTravel) score += 40;
  score += Math.min(recentFailures, 5) * 6;
  if (highValue) score += 25;
  if (offHours) score += 5;
  score = Math.min(score, 100);

  let level = 'low';
  if (score >= 70) level = 'high';
  else if (score >= 35) level = 'medium';

  const required = {
    low: ['totp'],
    medium: ['totp', 'transaction-otp-or-push'],
    high: ['totp', 'push-number-matching', 'manual-review'],
  }[level];

  return { score, level, required };
}
