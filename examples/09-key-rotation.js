import { KeyRing, randomBytes } from '../src/index.js';
const oldKey = randomBytes(32), newKey = randomBytes(32);
const stored = new KeyRing({ keys: { 1: oldKey }, current: 1 }).encrypt(Buffer.from('totp-seed'), 'alice');
const ring = new KeyRing({ keys: { 1: oldKey, 2: newKey }, current: 2 });
console.log('needs rotation:', ring.needsRotation(stored));
const migrated = ring.rotate(stored, 'alice');
console.log('migrated prefix:', migrated.slice(0, 3), '| still decrypts:', ring.decrypt(migrated, 'alice').toString());
