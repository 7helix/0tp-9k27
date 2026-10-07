// Small CBOR (RFC 8949) reader and writer, only what WebAuthn needs: integers, byte and text
// strings, arrays, maps, true/false/null. The reader is strict because it parses data from the
// network: bounded depth, lengths checked against the input, no indefinite lengths, no duplicate
// map keys, valid UTF-8 only.
const utf8 = new TextDecoder('utf-8', { fatal: true });
const MAX_DEPTH = 16;

function need(buf, offset, count) {
  if (offset + count > buf.length) throw new Error('cbor: truncated');
}

// Reads one item starting at `offset`. Returns the value and the offset just after it.
export function decodeFirst(buf, offset = 0, depth = 0) {
  if (depth > MAX_DEPTH) throw new Error('cbor: too deep');
  if (offset >= buf.length) throw new Error('cbor: truncated');

  const initial = buf[offset++];
  const major = initial >> 5;
  const info = initial & 31;

  if (major === 7) {
    if (info < 20 || info > 23) throw new Error('cbor: unsupported simple/float');
    const simple = { 20: false, 21: true, 22: null, 23: undefined };
    return { value: simple[info], offset };
  }

  // the "additional info" is either the value itself or says how many bytes hold the length
  let length;
  if (info < 24) {
    length = info;
  } else if (info === 24) {
    need(buf, offset, 1);
    length = buf[offset];
    offset += 1;
  } else if (info === 25) {
    need(buf, offset, 2);
    length = buf.readUInt16BE(offset);
    offset += 2;
  } else if (info === 26) {
    need(buf, offset, 4);
    length = buf.readUInt32BE(offset);
    offset += 4;
  } else if (info === 27) {
    need(buf, offset, 8);
    const big = buf.readBigUInt64BE(offset);
    offset += 8;
    if (big > BigInt(Number.MAX_SAFE_INTEGER)) throw new Error('cbor: integer too large');
    length = Number(big);
  } else {
    throw new Error('cbor: indefinite/reserved length unsupported');
  }

  switch (major) {
    case 0:
      return { value: length, offset };

    case 1:
      return { value: -1 - length, offset };

    case 2:
      need(buf, offset, length);
      return { value: Buffer.from(buf.subarray(offset, offset + length)), offset: offset + length };

    case 3:
      need(buf, offset, length);
      return { value: utf8.decode(buf.subarray(offset, offset + length)), offset: offset + length };

    case 4: {
      // every element takes at least one byte, so a bigger count than the input is a lie
      if (length > buf.length - offset) throw new Error('cbor: array length exceeds input');
      const items = [];
      for (let i = 0; i < length; i++) {
        const item = decodeFirst(buf, offset, depth + 1);
        items.push(item.value);
        offset = item.offset;
      }
      return { value: items, offset };
    }

    case 5: {
      if (length * 2 > buf.length - offset) throw new Error('cbor: map length exceeds input');
      const map = new Map();
      for (let i = 0; i < length; i++) {
        const key = decodeFirst(buf, offset, depth + 1);
        const value = decodeFirst(buf, key.offset, depth + 1);
        if (map.has(key.value)) throw new Error('cbor: duplicate map key');
        map.set(key.value, value.value);
        offset = value.offset;
      }
      return { value: map, offset };
    }

    case 6:
      // tags don't matter to us, read straight through to the tagged item
      return decodeFirst(buf, offset, depth + 1);

    default:
      throw new Error('cbor: bad major type');
  }
}

// Decodes exactly one item. Leftover bytes are an error.
export function decodeCbor(buf) {
  const { value, offset } = decodeFirst(Buffer.from(buf), 0);
  if (offset !== buf.length) throw new Error('cbor: trailing bytes');
  return value;
}

// ---- writer (used by the test authenticator, and handy for poking at things) ----

function header(major, n) {
  if (n < 24) return Buffer.from([(major << 5) | n]);
  if (n < 256) return Buffer.from([(major << 5) | 24, n]);
  if (n < 65536) {
    const out = Buffer.alloc(3);
    out[0] = (major << 5) | 25;
    out.writeUInt16BE(n, 1);
    return out;
  }
  if (n < 2 ** 32) {
    const out = Buffer.alloc(5);
    out[0] = (major << 5) | 26;
    out.writeUInt32BE(n, 1);
    return out;
  }
  const out = Buffer.alloc(9);
  out[0] = (major << 5) | 27;
  out.writeBigUInt64BE(BigInt(n), 1);
  return out;
}

export function encodeCbor(value) {
  if (value === null) return Buffer.from([0xf6]);
  if (value === undefined) return Buffer.from([0xf7]);
  if (value === true) return Buffer.from([0xf5]);
  if (value === false) return Buffer.from([0xf4]);

  if (typeof value === 'number') {
    return value >= 0 ? header(0, value) : header(1, -1 - value);
  }
  if (Buffer.isBuffer(value) || value instanceof Uint8Array) {
    return Buffer.concat([header(2, value.length), Buffer.from(value)]);
  }
  if (typeof value === 'string') {
    const bytes = Buffer.from(value, 'utf8');
    return Buffer.concat([header(3, bytes.length), bytes]);
  }
  if (Array.isArray(value)) {
    return Buffer.concat([header(4, value.length), ...value.map(encodeCbor)]);
  }

  const entries = value instanceof Map ? [...value] : Object.entries(value);
  const encoded = entries.flatMap(([k, v]) => [encodeCbor(k), encodeCbor(v)]);
  return Buffer.concat([header(5, entries.length), ...encoded]);
}
