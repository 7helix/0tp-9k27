import { shamir, randomBytes } from '../src/index.js';
const masterKey = randomBytes(32);
const { shares, fingerprint } = shamir.split(masterKey, 5, 3);
console.log('share 1:', shares[0]); console.log('fingerprint (store with the runbook):', fingerprint);
const recovered = shamir.combine([shares[4], shares[1], shares[2]], { fingerprint });
console.log('3 of 5 recover the key:', recovered.equals(masterKey));
try { shamir.combine([shares[0], shares[1]]); } catch (e) { console.log('2 of 5 fail:', e.message); }
