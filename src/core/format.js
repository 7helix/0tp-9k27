// Human-friendly formatting + input normalisation.
export const groupSecret = (b32, n = 4) => b32.replace(/\s/g, '').match(new RegExp(`.{1,${n}}`, 'g')).join(' ');
export const formatCode = (code) => (code.length === 6 ? `${code.slice(0, 3)} ${code.slice(3)}` : code.length === 8 ? `${code.slice(0, 4)} ${code.slice(4)}` : code);
export const maskCode = (code) => '*'.repeat(Math.max(0, code.length - 2)) + code.slice(-2);

// First code point (the digit ZERO) of common Unicode decimal-digit blocks.
const ZEROS = [0x30, 0x660, 0x6f0, 0x966, 0x9e6, 0xa66, 0xae6, 0xb66, 0xbe6, 0xc66, 0xce6, 0xd66, 0xff10];

/**
 * Normalise what a person typed: strips spaces/dashes and converts Arabic-Indic, Devanagari,
 * Bengali, Telugu, Tamil, full-width ... digits to ASCII. Users on non-Latin keyboards
 * will otherwise get "invalid code" for a correct code.
 */
export function normalizeNumericInput(input) {
  let out = '';
  for (const ch of String(input)) {
    const cp = ch.codePointAt(0);
    const zero = ZEROS.find((z) => cp >= z && cp <= z + 9);
    if (zero !== undefined) out += String(cp - zero);
    else if (!/[\s\-\u2010-\u2015.]/.test(ch)) out += ch;
  }
  return out;
}
