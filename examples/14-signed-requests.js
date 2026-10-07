import { signRequest, verifyRequest, MemoryStore, randomBytes } from '../src/index.js';
const secret = randomBytes(32), keys = { 'backend-1': secret }, store = new MemoryStore();
const body = JSON.stringify({ userId: 'u1', channel: 'sms', to: '+919876543210' });
const headers = signRequest({ method: 'POST', path: '/otp/send', body, keyId: 'backend-1', secret });
console.log(headers);
const check = (b = body) => verifyRequest({ method: 'POST', path: '/otp/send', body: b, headers, keys, store });
console.log('genuine  ->', await check());
console.log('replayed ->', await check());
console.log('tampered ->', await verifyRequest({ method: 'POST', path: '/otp/send', body: body.replace('+9198', '+1415'), headers: signRequest({ method: 'POST', path: '/otp/send', body, keyId: 'backend-1', secret }), keys, store }));
