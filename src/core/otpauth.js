// otpauth:// URIs (Key URI Format used by Google Authenticator, Authy, 1Password, ...)
export function buildOtpauthUri({ type = 'totp', issuer, account, secret, algorithm = 'SHA1', digits = 6, period = 30, counter = 0 }) {
  if (!issuer || !account || !secret) throw new Error('issuer, account and secret are required');
  const label = `${encodeURIComponent(issuer)}:${encodeURIComponent(account)}`;
  const p = new URLSearchParams({ secret, issuer, algorithm, digits: String(digits) });
  if (type === 'totp') p.set('period', String(period));
  else p.set('counter', String(counter));
  return `otpauth://${type}/${label}?${p.toString()}`;
}

export function parseOtpauthUri(uri) {
  const u = new URL(uri);
  if (u.protocol !== 'otpauth:') throw new Error('Not an otpauth URI');
  const [first, ...rest] = decodeURIComponent(u.pathname.replace(/^\//, '')).split(':');
  const account = rest.length ? rest.join(':') : first;
  const q = u.searchParams;
  return {
    type: u.hostname,
    issuer: q.get('issuer') || (rest.length ? first : undefined),
    account,
    secret: q.get('secret'),
    algorithm: (q.get('algorithm') || 'SHA1').toUpperCase(),
    digits: Number(q.get('digits') || 6),
    period: Number(q.get('period') || 30),
    counter: q.has('counter') ? Number(q.get('counter')) : undefined,
  };
}
