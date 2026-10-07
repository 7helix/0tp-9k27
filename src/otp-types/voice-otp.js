// Script for a voice call: digits read out slowly, said twice, so a text-to-speech engine can use it.
const WORDS = ['zero', 'one', 'two', 'three', 'four', 'five', 'six', 'seven', 'eight', 'nine'];

export function otpToSpeech(code, { brand = 'your service', repeat = 2 } = {}) {
  const spoken = String(code)
    .split('')
    .map((digit) => WORDS[Number(digit)] ?? digit)
    .join(', ');

  const parts = [];
  for (let i = 0; i < repeat; i++) {
    parts.push(`${i === 0 ? 'Your' : 'Again, your'} verification code is: ${spoken}.`);
  }

  return `Hello. This is ${brand}. ${parts.join(' ... ')} If you did not request this, hang up and do not share the code.`;
}
