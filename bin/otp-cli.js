#!/usr/bin/env node
import { randomBytes, base32Encode, base32Decode, totp, hotp, verifyTotp, buildOtpauthUri } from '../src/index.js';

const [command, ...args] = process.argv.slice(2);

const help = `otp-fortress CLI
  gen-key                                 new master key, pepper and API key for .env
  gen-secret                              new random TOTP secret (base32)
  totp <base32secret>                     current TOTP code
  hotp <base32secret> <counter>           HOTP code at a counter
  verify <base32secret> <code>            check a TOTP code (+/- 1 step)
  uri <issuer> <account> <base32secret>   otpauth:// link (paste into a QR generator)`;

switch (command) {
  case 'gen-key':
    console.log([
      `OTP_MASTER_KEY=${randomBytes(32).toString('hex')}`,
      `OTP_PEPPER=${randomBytes(32).toString('hex')}`,
      `OTP_API_KEY=${randomBytes(24).toString('hex')}`,
    ].join('\n'));
    break;

  case 'gen-secret':
    console.log(base32Encode(randomBytes(20)));
    break;

  case 'totp':
    console.log(totp(base32Decode(args[0])));
    break;

  case 'hotp':
    console.log(hotp(base32Decode(args[0]), Number(args[1])));
    break;

  case 'verify':
    console.log(verifyTotp(base32Decode(args[0]), args[1]).valid ? 'VALID' : 'INVALID');
    break;

  case 'uri':
    console.log(buildOtpauthUri({ issuer: args[0], account: args[1], secret: args[2] }));
    break;

  default:
    console.log(help);
}
