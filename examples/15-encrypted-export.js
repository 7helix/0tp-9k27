import { exportSecrets, importSecrets } from '../src/index.js';
const envelope = exportSecrets({ alice: 'JBSWY3DPEHPK3PXP' }, 'a long passphrase only alice knows');
console.log('safe to email:', envelope.slice(0, 90) + '...');
console.log('restored:', importSecrets(envelope, 'a long passphrase only alice knows'));
try { importSecrets(envelope, 'guess guess guess'); } catch (e) { console.log('wrong passphrase ->', e.message); }
