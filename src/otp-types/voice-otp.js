// Voice-call OTP text: digits spoken slowly, repeated, with pauses (for TTS engines).
const WORDS = ['zero', 'one', 'two', 'three', 'four', 'five', 'six', 'seven', 'eight', 'nine'];
export function otpToSpeech(code, { brand = 'your service', repeat = 2 } = {}) {
  const spoken = String(code).split('').map((d) => WORDS[Number(d)] ?? d).join(', ');
  const body = Array.from({ length: repeat }, (_, i) => `${i ? 'Again, your' : 'Your'} verification code is: ${spoken}.`).join(' ... ');
  return `Hello. This is ${brand}. ${body} If you did not request this, hang up and do not share the code.`;
}
