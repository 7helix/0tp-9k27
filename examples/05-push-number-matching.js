import { PushApproval, MemoryStore } from '../src/index.js';
const p = new PushApproval({ store: new MemoryStore() });
const r = await p.request({ userId: 'u1' });
console.log('Login screen shows:', r.displayNumber, '| phone offers:', r.deviceChoices);
console.log('User taps the matching number ->', await p.respond({ requestId: r.requestId, userId: 'u1', choice: r.displayNumber }));
console.log('Login page polls ->', await p.status(r.requestId));
