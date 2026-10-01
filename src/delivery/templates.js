// Message templates. The last line of the SMS uses the WebOTP / Apple "origin-bound code" format:
// "@example.com #123456" - browsers only autofill it on the matching domain (anti-phishing).
export function smsText({ code, brand, domain, ttlMin = 5 }) {
  return `${brand}: your verification code is ${code}. It expires in ${ttlMin} min. Never share it - we will never ask for it.\n\n@${domain} #${code}`;
}
export function emailContent({ code, brand, ttlMin = 5 }) {
  return {
    subject: `${code} is your ${brand} verification code`,
    text: `Your ${brand} verification code is ${code}.\nIt expires in ${ttlMin} minutes.\nIf you did not request it, ignore this email.`,
  };
}
