// Strict checks on anything that comes from outside. Reject bad input rather than quietly fixing it.
export class ValidationError extends Error {
  constructor(field) {
    super(`invalid_${field}`);
    this.field = field;
    this.status = 400;
  }
}

export const isUserId = (value) => typeof value === 'string' && /^[A-Za-z0-9_.:@-]{1,128}$/.test(value);
export const isE164 = (value) => typeof value === 'string' && /^\+[1-9]\d{7,14}$/.test(value);
export const isOtpCode = (value) => typeof value === 'string' && /^[0-9A-Za-z\s-]{4,32}$/.test(value);

export function isEmail(value) {
  if (typeof value !== 'string' || value.length > 254) return false;
  return /^[^\s@<>()\\,;:"]+@[^\s@<>()\\,;:"]+\.[A-Za-z]{2,}$/.test(value);
}

export function requireValid(field, value, predicate) {
  if (!predicate(value)) throw new ValidationError(field);
  return value;
}

export function validateDestination(channel, to) {
  if (channel === 'sms') return requireValid('to', to, isE164);
  if (channel === 'email') return requireValid('to', to, isEmail);
  throw new ValidationError('channel');
}
