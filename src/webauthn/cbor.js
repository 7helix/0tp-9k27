// Minimal CBOR (RFC 8949) - just what WebAuthn needs: ints, byte/text strings, arrays, maps, bool/null.
// Decoder is hardened for untrusted input: depth limit, length sanity checks, no indefinite lengths,
// duplicate map keys rejected, strict UTF-8.
const utf8 = new TextDecoder('utf-8', { fatal: true });

export function decodeFirst(buf, offset = 0, depth = 0) {
  if (depth > 16) throw new Error('cbor: too deep');
  if (offset >= buf.length) throw new Error('cbor: truncated');
  const ib = buf[offset++], major = ib >> 5, info = ib & 31;
  if (major === 7) {
    const simple = { 20: false, 21: true, 22: null, 23: undefined }[info];
    if (info < 20 || info > 23) throw new Error('cbor: unsupported simple/float');
    return { value: simple, offset };
  }
  let len;
  if (info < 24) len = info;
  else if (info === 24) { need(buf, offset, 1); len = buf[offset]; offset += 1; }
  else if (info === 25) { need(buf, offset, 2); len = buf.readUInt16BE(offset); offset += 2; }
  else if (info === 26) { need(buf, offset, 4); len = buf.readUInt32BE(offset); offset += 4; }
  else if (info === 27) {
    need(buf, offset, 8); const big = buf.readBigUInt64BE(offset); offset += 8;
    if (big > BigInt(Number.MAX_SAFE_INTEGER)) throw new Error('cbor: integer too large');
    len = Number(big);
  } else throw new Error('cbor: indefinite/reserved length unsupported');

  switch (major) {
    case 0: return { value: len, offset };
    case 1: return { value: -1 - len, offset };
    case 2: need(buf, offset, len); return { value: Buffer.from(buf.subarray(offset, offset + len)), offset: offset + len };
    case 3: need(buf, offset, len); return { value: utf8.decode(buf.subarray(offset, offset + len)), offset: offset + len };
    case 4: {
      if (len > buf.length - offset) throw new Error('cbor: array length exceeds input');
      const arr = [];
      for (let i = 0; i < len; i++) { const r = decodeFirst(buf, offset, depth + 1); arr.push(r.value); offset = r.offset; }
      return { value: arr, offset };
    }
    case 5: {
      if (len * 2 > buf.length - offset) throw new Error('cbor: map length exceeds input');
      const map = new Map();
      for (let i = 0; i < len; i++) {
        const k = decodeFirst(buf, offset, depth + 1); const v = decodeFirst(buf, k.offset, depth + 1);
        if (map.has(k.value)) throw new Error('cbor: duplicate map key');
        map.set(k.value, v.value); offset = v.offset;
      }
      return { value: map, offset };
    }
    case 6: return decodeFirst(buf, offset, depth + 1);            // tags are transparent here
    default: throw new Error('cbor: bad major type');
  }
}
const need = (buf, off, n) => { if (off + n > buf.length) throw new Error('cbor: truncated'); };

/** Decode exactly one item; trailing bytes are an error. */
export function decodeCbor(buf) {
  const { value, offset } = decodeFirst(Buffer.from(buf), 0);
  if (offset !== buf.length) throw new Error('cbor: trailing bytes');
  return value;
}

// ---- encoder (used by the test authenticator and handy for learning) ----
const head = (major, n) => {
  if (n < 24) return Buffer.from([(major << 5) | n]);
  if (n < 256) return Buffer.from([(major << 5) | 24, n]);
  if (n < 65536) { const b = Buffer.alloc(3); b[0] = (major << 5) | 25; b.writeUInt16BE(n, 1); return b; }
  if (n < 2 ** 32) { const b = Buffer.alloc(5); b[0] = (major << 5) | 26; b.writeUInt32BE(n, 1); return b; }
  const b = Buffer.alloc(9); b[0] = (major << 5) | 27; b.writeBigUInt64BE(BigInt(n), 1); return b;
};
export function encodeCbor(v) {
  if (v === null) return Buffer.from([0xf6]);
  if (v === undefined) return Buffer.from([0xf7]);
  if (v === true) return Buffer.from([0xf5]);
  if (v === false) return Buffer.from([0xf4]);
  if (typeof v === 'number') return v >= 0 ? head(0, v) : head(1, -1 - v);
  if (Buffer.isBuffer(v) || v instanceof Uint8Array) return Buffer.concat([head(2, v.length), Buffer.from(v)]);
  if (typeof v === 'string') { const b = Buffer.from(v, 'utf8'); return Buffer.concat([head(3, b.length), b]); }
  if (Array.isArray(v)) return Buffer.concat([head(4, v.length), ...v.map(encodeCbor)]);
  const entries = v instanceof Map ? [...v] : Object.entries(v);
  return Buffer.concat([head(5, entries.length), ...entries.flatMap(([k, val]) => [encodeCbor(k), encodeCbor(val)])]);
}
