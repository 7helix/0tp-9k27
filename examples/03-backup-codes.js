import { BackupCodes, MemoryStore } from '../src/index.js';
const b = new BackupCodes({ store: new MemoryStore() });
const codes = await b.generate('user-1');
console.log('Show ONCE to the user:', codes);
console.log('use first  ->', await b.consume('user-1', codes[0]));
console.log('reuse first ->', await b.consume('user-1', codes[0]));
