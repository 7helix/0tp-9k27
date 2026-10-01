// IP allowlists and safe client-IP extraction. IPv4 + IPv6 (+ IPv4-mapped IPv6), no dependencies.
const v4 = (s) => {
  const p = s.split('.');
  if (p.length !== 4 || p.some((x) => !/^\d{1,3}$/.test(x) || Number(x) > 255)) return null;
  return p.reduce((a, x) => (a << 8n) | BigInt(x), 0n);
};
function v6(str) {
  let a = str.split('%')[0].toLowerCase();
  if (a.includes('.')) {                              // embedded IPv4 tail (::ffff:1.2.3.4)
    const i = a.lastIndexOf(':'); const t = v4(a.slice(i + 1)); if (t === null) return null;
    a = `${a.slice(0, i + 1)}${((t >> 16n) & 0xffffn).toString(16)}:${(t & 0xffffn).toString(16)}`;
  }
  if ((a.match(/::/g) || []).length > 1) return null;
  const [head, tail] = a.split('::');
  const h = head ? head.split(':') : [], t = tail ? tail.split(':') : [];
  const groups = a.includes('::') ? [...h, ...Array(8 - h.length - t.length).fill('0'), ...t] : h;
  if (groups.length !== 8 || groups.some((g) => !/^[0-9a-f]{1,4}$/.test(g))) return null;
  return groups.reduce((acc, g) => (acc << 16n) | BigInt(parseInt(g, 16)), 0n);
}
export function parseIp(ip) {
  if (typeof ip !== 'string') return null;
  if (!ip.includes(':')) { const n = v4(ip); return n === null ? null : { v: 4, n }; }
  const n = v6(ip); if (n === null) return null;
  return n >> 32n === 0xffffn ? { v: 4, n: n & 0xffffffffn } : { v: 6, n };   // unmap ::ffff:a.b.c.d
}
export function parseCidr(c) {
  const [addr, len] = String(c).split('/');
  const ip = parseIp(addr); if (!ip) throw new Error(`bad CIDR: ${c}`);
  const bits = ip.v === 4 ? 32 : 128; const prefix = len === undefined ? bits : Number(len);
  if (!Number.isInteger(prefix) || prefix < 0 || prefix > bits) throw new Error(`bad CIDR prefix: ${c}`);
  return { ...ip, prefix };
}
export function ipInCidr(ip, cidr) {
  const a = parseIp(ip), c = typeof cidr === 'string' ? parseCidr(cidr) : cidr;
  if (!a || a.v !== c.v) return false;
  const shift = BigInt((a.v === 4 ? 32 : 128) - c.prefix);
  return a.n >> shift === c.n >> shift;
}
export const matchesAny = (ip, cidrs) => cidrs.some((c) => ipInCidr(ip, c));

/**
 * The real client IP. X-Forwarded-For is attacker-controlled unless it came from a proxy YOU run, so we
 * only read it when the TCP peer is in `trustedProxies`, and then walk it right-to-left past trusted hops.
 */
export function clientIp(req, trustedProxies = []) {
  const peer = req.socket?.remoteAddress || '';
  if (!trustedProxies.length || !matchesAny(peer, trustedProxies)) return peer;
  const chain = String(req.headers['x-forwarded-for'] || '').split(',').map((s) => s.trim()).filter(Boolean);
  for (let i = chain.length - 1; i >= 0; i--) if (parseIp(chain[i]) && !matchesAny(chain[i], trustedProxies)) return chain[i];
  return peer;
}
