// Google-Authenticator-compatible 2FA in ~20 lines (no service layer, just the primitives).
import { randomBytes, base32Encode, base32Decode, totp, verifyTotp, buildOtpauthUri } from '../src/index.js';

const secret = randomBytes(20);                       // 160-bit seed, as RFC 4226 recommends
const b32 = base32Encode(secret);
console.log('Secret (show once, then store encrypted):', b32);
console.log('Scan as QR:', buildOtpauthUri({ issuer: 'DemoApp', account: 'you@example.com', secret: b32 }));

const code = totp(base32Decode(b32));
console.log('Current code:', code);
console.log('Verify:', verifyTotp(base32Decode(b32), code));
console.log('Verify wrong:', verifyTotp(base32Decode(b32), '000000'));
