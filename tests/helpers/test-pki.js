// Real X.509 certificates for the attestation tests. Node can parse certificates but not create
// them, so we shell out to the openssl CLI. Tests skip themselves when it isn't installed.
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';

function openSslAvailable() {
  try {
    execFileSync('openssl', ['version'], { stdio: 'ignore' });
    return true;
  } catch {
    return false;
  }
}

export const haveOpenssl = openSslAvailable();

const EC_KEY = ['-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes'];
const AAGUID_OID = '1.3.6.1.4.1.45724.1.1.4';

const openssl = (dir, args) => execFileSync('openssl', args, { cwd: dir, stdio: 'ignore' });
const toDer = (dir, pemFile) => execFileSync('openssl', ['x509', '-in', pemFile, '-outform', 'DER'], { cwd: dir });
const withColons = (hex) => hex.match(/../g).join(':');

// Builds a root CA (and optionally an intermediate), plus a leaf attestation certificate that carries
// an AAGUID extension. The options let tests produce deliberately bad certificates.
export function makePki({
  aaguidHex = 'ee882879721c491397753dfcce97072a',
  withIntermediate = false,
  leafCA = false,
  ou = 'Authenticator Attestation',
  criticalAaguid = false,
  noAaguid = false,
  days = 30,
} = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pki-'));

  openssl(dir, [
    'req', '-x509', ...EC_KEY,
    '-keyout', 'root.key', '-out', 'root.pem', '-days', '3650',
    '-subj', '/C=US/O=Test Root CA/CN=Test Root',
    '-addext', 'basicConstraints=critical,CA:TRUE',
    '-addext', 'keyUsage=critical,keyCertSign',
  ]);

  let issuer = 'root';
  if (withIntermediate) {
    openssl(dir, [
      'req', '-new', ...EC_KEY,
      '-keyout', 'int.key', '-out', 'int.csr',
      '-subj', '/C=US/O=Test Intermediate/CN=Test Intermediate CA',
    ]);
    fs.writeFileSync(
      path.join(dir, 'int.ext'),
      'basicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign\n',
    );
    openssl(dir, [
      'x509', '-req', '-in', 'int.csr', '-CA', 'root.pem', '-CAkey', 'root.key', '-CAcreateserial',
      '-out', 'int.pem', '-days', '3000', '-extfile', 'int.ext',
    ]);
    issuer = 'int';
  }

  let leafCount = 0;
  function makeLeaf(overrides = {}) {
    const name = `leaf${leafCount++}`;
    const leafAaguid = overrides.aaguidHex ?? aaguidHex;

    openssl(dir, [
      'req', '-new', ...EC_KEY,
      '-keyout', `${name}.key`, '-out', `${name}.csr`,
      '-subj', `/C=US/O=Test Vendor/OU=${ou}/CN=Test Attestation`,
    ]);

    const extensions = [`basicConstraints=critical,CA:${leafCA ? 'TRUE' : 'FALSE'}`];
    if (!noAaguid) {
      const critical = criticalAaguid ? 'critical,' : '';
      extensions.push(`${AAGUID_OID}=${critical}DER:04:10:${withColons(leafAaguid)}`);
    }
    fs.writeFileSync(path.join(dir, `${name}.ext`), `${extensions.join('\n')}\n`);

    openssl(dir, [
      'x509', '-req', '-in', `${name}.csr`, '-CA', `${issuer}.pem`, '-CAkey', `${issuer}.key`, '-CAcreateserial',
      '-out', `${name}.pem`, '-days', String(days), '-extfile', `${name}.ext`,
    ]);

    return {
      leafDer: toDer(dir, `${name}.pem`),
      leafKey: crypto.createPrivateKey(fs.readFileSync(path.join(dir, `${name}.key`))),
      aaguidHex: leafAaguid,
    };
  }

  const first = makeLeaf();
  const intermediateDer = withIntermediate ? toDer(dir, 'int.pem') : null;
  const chainFor = (leafDer) => (withIntermediate ? [leafDer, intermediateDer] : [leafDer]);

  return {
    dir,
    aaguidHex,
    rootPem: fs.readFileSync(path.join(dir, 'root.pem'), 'utf8'),
    rootDer: toDer(dir, 'root.pem'),
    intDer: intermediateDer,
    leafDer: first.leafDer,
    leafKey: first.leafKey,
    x5c: chainFor(first.leafDer),

    // Another leaf from the same root, for example a different authenticator model from the same vendor.
    issueLeaf(overrides) {
      const leaf = makeLeaf(overrides);
      return { ...leaf, x5c: chainFor(leaf.leafDer) };
    },

    cleanup() {
      fs.rmSync(dir, { recursive: true, force: true });
    },
  };
}
