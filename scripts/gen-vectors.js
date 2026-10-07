#!/usr/bin/env node
// Prints the official RFC 4226 / 6238 test vectors as this code computes them.
// Handy when porting to another language: the output should match your port exactly.
import { hotp, totp } from '../src/index.js';

const secret = Buffer.from('12345678901234567890');

console.log('RFC 4226 (HOTP, SHA1, 6 digits)');
for (let counter = 0; counter < 10; counter++) {
  console.log(`  counter ${counter}: ${hotp(secret, counter)}`);
}

console.log('RFC 6238 (TOTP, SHA1, 8 digits)');
for (const seconds of [59, 1111111109, 1111111111, 1234567890, 2000000000, 20000000000]) {
  console.log(`  t=${seconds}: ${totp(secret, { time: seconds * 1000, digits: 8 })}`);
}
