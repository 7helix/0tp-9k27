// Formatting codes for people, and cleaning up what they type back.
export function groupSecret(base32, size = 4) {
  const groups = base32.replace(/\s/g, '').match(new RegExp(`.{1,${size}}`, 'g'));
  return groups.join(' ');
}

export function formatCode(code) {
  if (code.length === 6) return `${code.slice(0, 3)} ${code.slice(3)}`;
  if (code.length === 8) return `${code.slice(0, 4)} ${code.slice(4)}`;
  return code;
}

export function maskCode(code) {
  return '*'.repeat(Math.max(0, code.length - 2)) + code.slice(-2);
}

// The code point of "0" in some common digit sets (ASCII, Arabic-Indic, Devanagari, Bengali, Telugu, ...).
const ZERO_CODE_POINTS = [0x30, 0x660, 0x6f0, 0x966, 0x9e6, 0xa66, 0xae6, 0xb66, 0xbe6, 0xc66, 0xce6, 0xd66, 0xff10];

// Strips spaces and dashes and turns digits from other scripts into ASCII. Without this, someone
// whose keyboard types Telugu or Devanagari digits gets "invalid code" for a correct code.
export function normalizeNumericInput(input) {
  let out = '';
  for (const char of String(input)) {
    const codePoint = char.codePointAt(0);
    const zero = ZERO_CODE_POINTS.find((z) => codePoint >= z && codePoint <= z + 9);

    if (zero !== undefined) out += String(codePoint - zero);
    else if (!/[\s\-\u2010-\u2015.]/.test(char)) out += char;
  }
  return out;
}
