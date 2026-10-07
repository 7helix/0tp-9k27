import { FailoverProvider, MemoryProvider } from '../src/index.js';
class FlakySms { async send() { throw new Error('gateway 503'); } }
const backup = new MemoryProvider();
const p = new FailoverProvider([new FlakySms(), backup], { maxFailures: 2 });
for (let i = 0; i < 3; i++) console.log(await p.send({ channel: 'sms', to: '+919876543210', message: { text: 'code 123456' } }));
