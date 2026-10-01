import { QrLogin, MemoryStore } from '../src/index.js';
const q = new QrLogin({ store: new MemoryStore() });
const s = await q.create({ meta: { device: 'Chrome on Windows' } });
console.log('Browser shows QR with:', s.qrPayload);
console.log('Browser polls ->', await q.claim({ sessionId: s.sessionId, pollToken: s.pollToken }));
const nonce = new URL(s.qrPayload.replace('otpf://', 'https://')).searchParams.get('n');
console.log('Phone (logged in as alice) approves ->', await q.approve({ sessionId: s.sessionId, nonce, userId: 'alice' }));
console.log('Browser polls ->', await q.claim({ sessionId: s.sessionId, pollToken: s.pollToken }));
