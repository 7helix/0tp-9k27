#!/usr/bin/env node
// Prints the official RFC 4226 / 6238 test vectors as computed by THIS codebase - handy when porting to another language.
import { hotp, totp } from '../src/index.js';
const S1 = Buffer.from('12345678901234567890');
console.log('RFC 4226 (HOTP, SHA1, 6 digits)');
for (let i = 0; i < 10; i++) console.log(`  counter ${i}: ${hotp(S1, i)}`);
console.log('RFC 6238 (TOTP, SHA1, 8 digits)');
for (const t of [59, 1111111109, 1111111111, 1234567890, 2000000000, 20000000000]) console.log(`  t=${t}: ${totp(S1, { time: t * 1000, digits: 8 })}`);
