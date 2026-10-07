// Restrict enrolment to ONE hardware model using attestation. Needs the `openssl` CLI (it mints a demo vendor PKI).
import { WebAuthn, MemoryStore } from '../src/index.js';
import { FakeAuthenticator } from '../tests/helpers/fake-authenticator.js';
import { makePki, haveOpenssl } from '../tests/helpers/test-pki.js';

if (!haveOpenssl) { console.log('openssl not found - skipping demo'); process.exit(0); }
const ALLOWED = 'ee882879721c491397753dfcce97072a', OTHER = '2fc0579f811347eab116bb5a8db9202a';
const vendor = makePki({ aaguidHex: ALLOWED }), rogue = makePki({ aaguidHex: ALLOWED }); // rogue CA claims the same model!
const wa = new WebAuthn({ store: new MemoryStore(), rpId: 'example.com', origins: ['https://example.com'],
  attestation: { formats: ['packed'], trustAnchors: [vendor.rootPem], aaguidAllowlist: [ALLOWED] } });
const attempt = async (label, pki, aaguid, kind = 'packed') => {
  const dev = new FakeAuthenticator({ aaguid }); const start = await wa.startRegistration({ userId: label, userName: label });
  const r = await wa.finishRegistration({ userId: label, response: dev.create(start.options, { attestation: { kind, certKey: pki?.leafKey, x5c: pki?.x5c } }) });
  console.log(label.padEnd(34), r.ok ? `ACCEPTED ${JSON.stringify(r.attestation)}` : `rejected: ${r.reason}`);
};
await attempt('genuine key from the vendor', vendor, ALLOWED);
await attempt('self-attestation claiming the model', null, ALLOWED, 'packed-self');
await attempt('rogue CA claiming the model', rogue, ALLOWED);
await attempt('trusted vendor, but a different model', vendor.issueLeaf({ aaguidHex: OTHER }), OTHER);
for (const p of [vendor, rogue]) p.cleanup();
