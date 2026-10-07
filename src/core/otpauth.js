// otpauth:// links, the format authenticator apps read from a QR code.
export function buildOtpauthUri({
  type = 'totp',
  issuer,
  account,
  secret,
  algorithm = 'SHA1',
  digits = 6,
  period = 30,
  counter = 0,
}) {
  if (!issuer || !account || !secret) throw new Error('issuer, account and secret are required');

  const label = `${encodeURIComponent(issuer)}:${encodeURIComponent(account)}`;
  const params = new URLSearchParams({ secret, issuer, algorithm, digits: String(digits) });
  if (type === 'totp') params.set('period', String(period));
  else params.set('counter', String(counter));

  return `otpauth://${type}/${label}?${params}`;
}

export function parseOtpauthUri(uri) {
  const url = new URL(uri);
  if (url.protocol !== 'otpauth:') throw new Error('Not an otpauth URI');

  // the label is "Issuer:account", or just "account"
  const [first, ...rest] = decodeURIComponent(url.pathname.replace(/^\//, '')).split(':');
  const account = rest.length ? rest.join(':') : first;
  const params = url.searchParams;

  return {
    type: url.hostname,
    issuer: params.get('issuer') || (rest.length ? first : undefined),
    account,
    secret: params.get('secret'),
    algorithm: (params.get('algorithm') || 'SHA1').toUpperCase(),
    digits: Number(params.get('digits') || 6),
    period: Number(params.get('period') || 30),
    counter: params.has('counter') ? Number(params.get('counter')) : undefined,
  };
}
