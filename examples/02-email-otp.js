// Full email/SMS OTP flow through the hardened service.
import { OtpService, MemoryStore, ConsoleProvider, randomBytes } from '../src/index.js';

const svc = new OtpService({ store: new MemoryStore(), masterKey: randomBytes(32), pepper: randomBytes(32).toString('hex'), provider: new ConsoleProvider(), brand: 'DemoApp', domain: 'demo.example' });
console.log(await svc.sendOtp({ userId: 'user-42', channel: 'email', to: 'alice@example.com' }));
console.log('wrong code ->', await svc.verifyOtp({ userId: 'user-42', code: '000000' }));
console.log('audit trail:', svc.audit.entries.map((e) => e.event));
