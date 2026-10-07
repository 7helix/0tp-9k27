// OTP messages in several languages.
//
// Heads up: an SMS with non-GSM characters (Hindi, Telugu, Arabic, ...) goes out as UCS-2, which only
// fits 70 characters per segment instead of 160. Keep these short or expect 2-3 segments.
const MESSAGES = {
  en: 'Your {brand} verification code is {code}. It expires in {ttl} minutes. Do not share it with anyone.',
  hi: 'आपका {brand} सत्यापन कोड {code} है। यह {ttl} मिनट में समाप्त हो जाएगा। इसे किसी के साथ साझा न करें।',
  te: 'మీ {brand} ధృవీకరణ కోడ్ {code}. ఇది {ttl} నిమిషాల్లో ముగుస్తుంది. దీన్ని ఎవరితోనూ పంచుకోవద్దు.',
  es: 'Tu código de verificación de {brand} es {code}. Caduca en {ttl} minutos. No lo compartas con nadie.',
  fr: 'Votre code de vérification {brand} est {code}. Il expire dans {ttl} minutes. Ne le partagez avec personne.',
  de: 'Ihr {brand}-Bestätigungscode lautet {code}. Er läuft in {ttl} Minuten ab. Geben Sie ihn niemals weiter.',
};

export function supportedLanguages() {
  return Object.keys(MESSAGES);
}

export function localizedSms({ lang = 'en', brand, code, domain, ttlMin = 5 }) {
  const language = String(lang).toLowerCase().split('-')[0]; // "hi-IN" -> "hi"
  const template = MESSAGES[language] || MESSAGES.en;

  const text = template
    .replace('{brand}', brand)
    .replace('{code}', code)
    .replace('{ttl}', String(ttlMin));

  return domain ? `${text}\n\n@${domain} #${code}` : text;
}
