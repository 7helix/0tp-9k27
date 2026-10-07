import { DeviceTrust, MemoryStore, randomBytes } from '../src/index.js';
const dt = new DeviceTrust({ store: new MemoryStore(), key: randomBytes(32) });
const { id, token } = await dt.issue('alice', { label: 'Alice laptop', ttlDays: 30 });
console.log('Set as HttpOnly+Secure+SameSite cookie:', token.slice(0, 32) + '...');
console.log('Skip 2FA?', await dt.check('alice', token));
await dt.revoke('alice', id);
console.log('After revoke:', await dt.check('alice', token));
