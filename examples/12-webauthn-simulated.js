// A full passkey registration + login against the verifier, using a software authenticator.
import { WebAuthn, MemoryStore } from '../src/index.js';
import { FakeAuthenticator } from '../tests/helpers/fake-authenticator.js';

const wa = new WebAuthn({ store: new MemoryStore(), rpId: 'example.com', rpName: 'Demo', origins: ['https://example.com'] });
const device = new FakeAuthenticator({ alg: 'ES256' });
const reg = await wa.startRegistration({ userId: 'alice', userName: 'alice@example.com' });
console.log('register ->', await wa.finishRegistration({ userId: 'alice', response: device.create(reg.options) }));
const a1 = await wa.startAuthentication({ userId: 'alice' });
console.log('login    ->', await wa.finishAuthentication({ userId: 'alice', response: device.get(a1.options) }));
const a2 = await wa.startAuthentication({ userId: 'alice' });
console.log('phishing ->', await wa.finishAuthentication({ userId: 'alice', response: device.get(a2.options, { origin: 'https://examp1e.com' }) }));
