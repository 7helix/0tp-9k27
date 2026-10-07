// IP allowlists and finding the real client IP. Handles IPv4, IPv6 and IPv4-mapped IPv6.
function parseV4(text) {
  const parts = text.split('.');
  if (parts.length !== 4) return null;
  if (parts.some((p) => !/^\d{1,3}$/.test(p) || Number(p) > 255)) return null;
  return parts.reduce((acc, part) => (acc << 8n) | BigInt(part), 0n);
}

function parseV6(text) {
  let address = text.split('%')[0].toLowerCase(); // drop a zone id like %eth0

  // an IPv4 tail (::ffff:1.2.3.4) becomes two hex groups
  if (address.includes('.')) {
    const lastColon = address.lastIndexOf(':');
    const tail = parseV4(address.slice(lastColon + 1));
    if (tail === null) return null;
    const high = ((tail >> 16n) & 0xffffn).toString(16);
    const low = (tail & 0xffffn).toString(16);
    address = `${address.slice(0, lastColon + 1)}${high}:${low}`;
  }

  if ((address.match(/::/g) || []).length > 1) return null;

  const [head, tail] = address.split('::');
  const headGroups = head ? head.split(':') : [];
  const tailGroups = tail ? tail.split(':') : [];

  let groups = headGroups;
  if (address.includes('::')) {
    const missing = 8 - headGroups.length - tailGroups.length;
    groups = [...headGroups, ...Array(missing).fill('0'), ...tailGroups];
  }
  if (groups.length !== 8 || groups.some((g) => !/^[0-9a-f]{1,4}$/.test(g))) return null;

  return groups.reduce((acc, group) => (acc << 16n) | BigInt(parseInt(group, 16)), 0n);
}

export function parseIp(ip) {
  if (typeof ip !== 'string') return null;

  if (!ip.includes(':')) {
    const n = parseV4(ip);
    return n === null ? null : { v: 4, n };
  }

  const n = parseV6(ip);
  if (n === null) return null;
  // ::ffff:a.b.c.d is really an IPv4 address
  if (n >> 32n === 0xffffn) return { v: 4, n: n & 0xffffffffn };
  return { v: 6, n };
}

export function parseCidr(text) {
  const [address, lengthText] = String(text).split('/');
  const ip = parseIp(address);
  if (!ip) throw new Error(`bad CIDR: ${text}`);

  const totalBits = ip.v === 4 ? 32 : 128;
  const prefix = lengthText === undefined ? totalBits : Number(lengthText);
  if (!Number.isInteger(prefix) || prefix < 0 || prefix > totalBits) throw new Error(`bad CIDR prefix: ${text}`);

  return { ...ip, prefix };
}

export function ipInCidr(ip, cidr) {
  const parsed = parseIp(ip);
  const range = typeof cidr === 'string' ? parseCidr(cidr) : cidr;
  if (!parsed || parsed.v !== range.v) return false;

  const hostBits = BigInt((parsed.v === 4 ? 32 : 128) - range.prefix);
  return parsed.n >> hostBits === range.n >> hostBits;
}

export function matchesAny(ip, cidrs) {
  return cidrs.some((cidr) => ipInCidr(ip, cidr));
}

// X-Forwarded-For is just a header, so anyone can fake it. We only read it when the connection came
// from a proxy we trust, and then take the right-most address that isn't one of our own proxies.
export function clientIp(req, trustedProxies = []) {
  const peer = req.socket?.remoteAddress || '';
  if (trustedProxies.length === 0 || !matchesAny(peer, trustedProxies)) return peer;

  const chain = String(req.headers['x-forwarded-for'] || '')
    .split(',')
    .map((entry) => entry.trim())
    .filter(Boolean);

  for (let i = chain.length - 1; i >= 0; i--) {
    if (parseIp(chain[i]) && !matchesAny(chain[i], trustedProxies)) return chain[i];
  }
  return peer;
}
