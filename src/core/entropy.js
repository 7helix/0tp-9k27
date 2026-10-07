// Turns "is a 6 digit code safe?" into numbers, for picking code lengths and attempt limits.
export function codeSpaceBits(alphabetSize, length) {
  return length * Math.log2(alphabetSize);
}

// Chance that someone making `attempts` guesses hits a valid code.
export function successProbability({ alphabetSize = 10, length = 6, attempts = 1, validCodes = 1 }) {
  return Math.min(1, (attempts * validCodes) / alphabetSize ** length);
}

// Shortest code length that keeps that chance at or below `target`.
export function minLengthFor({ alphabetSize = 10, attempts, target, validCodes = 1 }) {
  for (let length = 1; length <= 32; length++) {
    if (successProbability({ alphabetSize, length, attempts, validCodes }) <= target) return length;
  }
  return null;
}

export function compare({ attempts = 5 } = {}) {
  const configs = [
    ['6 digits', 10, 6],
    ['8 digits', 10, 8],
    ['6 alnum (29)', 29, 6],
    ['8 alnum (29)', 29, 8],
    ['10 alnum (29)', 29, 10],
  ];
  return configs.map(([name, alphabetSize, length]) => ({
    name,
    bits: +codeSpaceBits(alphabetSize, length).toFixed(1),
    pSuccess: successProbability({ alphabetSize, length, attempts }),
  }));
}
