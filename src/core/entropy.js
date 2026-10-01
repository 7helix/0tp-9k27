// Turn "is a 6-digit code safe?" into numbers. Great for teaching and for choosing parameters.
export const codeSpaceBits = (alphabetSize, length) => length * Math.log2(alphabetSize);

/** Probability an attacker who makes `attempts` guesses hits a valid code. */
export function successProbability({ alphabetSize = 10, length = 6, attempts = 1, validCodes = 1 }) {
  return Math.min(1, (attempts * validCodes) / alphabetSize ** length);
}

/** Smallest code length that keeps the attacker's success probability <= target. */
export function minLengthFor({ alphabetSize = 10, attempts, target, validCodes = 1 }) {
  for (let len = 1; len <= 32; len++) {
    if (successProbability({ alphabetSize, length: len, attempts, validCodes }) <= target) return len;
  }
  return null;
}

/** Human-readable comparison of common configurations. */
export function compare({ attempts = 5 } = {}) {
  const rows = [
    ['6 digits', 10, 6], ['8 digits', 10, 8], ['6 alnum (29)', 29, 6], ['8 alnum (29)', 29, 8], ['10 alnum (29)', 29, 10],
  ];
  return rows.map(([name, size, len]) => ({
    name, bits: +codeSpaceBits(size, len).toFixed(1),
    pSuccess: successProbability({ alphabetSize: size, length: len, attempts }),
  }));
}
