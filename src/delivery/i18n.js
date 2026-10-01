// Localised OTP messages. NOTE: SMS containing non-GSM characters (Hindi, Telugu, Arabic...) is sent
// as UCS-2 and fits only 70 chars per segment (vs 160) - keep them short or budget for 2-3 segments.
const BODY = {
  en: 'Your {brand} verification code is {code}. It expires in {ttl} minutes. Do not share it with anyone.',
  hi: 'आपका {brand} सत्यापन कोड {code} है। यह {ttl} मिनट में समाप्त हो जाएगा। इसे किसी के साथ साझा न करें।',
  te: 'మీ {brand} ధృవీకరణ కోడ్ {code}. ఇది {ttl} నిమిషాల్లో ముగుస్తుంది. దీన్ని ఎవరితోనూ పంచుకోవద్దు.',
  es: 'Tu código de verificación de {brand} es {code}. Caduca en {ttl} minutos. No lo compartas con nadie.',
  fr: 'Votre code de vérification {brand} est {code}. Il expire dans {ttl} minutes. Ne le partagez avec personne.',
  de: 'Ihr {brand}-Bestätigungscode lautet {code}. Er läuft in {ttl} Minuten ab. Geben Sie ihn niemals weiter.',
};
export const supportedLanguages = () => Object.keys(BODY);

export function localizedSms({ lang = 'en', brand, code, domain, ttlMin = 5 }) {
  const base = (BODY[String(lang).toLowerCase().split('-')[0]] || BODY.en)
    .replace('{brand}', brand).replace('{code}', code).replace('{ttl}', String(ttlMin));
  return domain ? `${base}\n\n@${domain} #${code}` : base;
}
