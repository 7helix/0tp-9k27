// Message templates. The SMS ends with "@example.com #123456", the format browsers and phones use to
// autofill a code only on the site it belongs to, which helps against phishing pages.
export function smsText({ code, brand, domain, ttlMin = 5 }) {
  const body = `${brand}: your verification code is ${code}. It expires in ${ttlMin} min. `
    + 'Never share it - we will never ask for it.';
  return `${body}\n\n@${domain} #${code}`;
}

export function emailContent({ code, brand, ttlMin = 5 }) {
  return {
    subject: `${code} is your ${brand} verification code`,
    text: [
      `Your ${brand} verification code is ${code}.`,
      `It expires in ${ttlMin} minutes.`,
      'If you did not request it, ignore this email.',
    ].join('\n'),
  };
}
