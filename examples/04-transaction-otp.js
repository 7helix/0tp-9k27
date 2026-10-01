import { TransactionOtp, MemoryStore, randomBytes } from '../src/index.js';
const t = new TransactionOtp({ store: new MemoryStore(), masterKey: randomBytes(32) });
const tx = { amount: '25000.00', currency: 'INR', payee: 'ACME-LTD-8841' };
const { nonce, code, summary } = await t.issue({ userId: 'u1', tx });
console.log('Sent to user with the summary:', summary, '| code:', code);
console.log('Attacker swaps payee ->', await t.verify({ userId: 'u1', tx: { ...tx, payee: 'ATTACKER-0001' }, nonce, code }));
console.log('Honest transaction  ->', await t.verify({ userId: 'u1', tx, nonce, code }));
