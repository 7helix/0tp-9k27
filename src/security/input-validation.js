// Strict validators. Reject early, reject loudly; never "fix" attacker-controlled input silently.
export class ValidationError extends Error { constructor(field) { super(`invalid_${field}`); this.field = field; this.status = 400; } }

export const isUserId = (v) => typeof v === 'string' && /^[A-Za-z0-9_.:@-]{1,128}$/.test(v);
export const isE164 = (v) => typeof v === 'string' && /^\+[1-9]\d{7,14}$/.test(v);
export const isEmail = (v) => typeof v === 'string' && v.length <= 254 && /^[^\s@<>()\\,;:"]+@[^\s@<>()\\,;:"]+\.[A-Za-z]{2,}$/.test(v);
export const isOtpCode = (v) => typeof v === 'string' && /^[0-9A-Za-z\s-]{4,32}$/.test(v);

export function requireValid(field, value, predicate) {
  if (!predicate(value)) throw new ValidationError(field);
  return value;
}
/** Validate the destination for a channel. */
export function validateDestination(channel, to) {
  if (channel === 'sms') return requireValid('to', to, isE164);
  if (channel === 'email') return requireValid('to', to, isEmail);
  throw new ValidationError('channel');
}
