// Attestation checking for new passkeys: formats none, packed (self and certificate) and fido-u2f.
//
// Attestation only answers "was this key made by hardware from a vendor I trust?". It matters if you
// want to limit which authenticators can enrol, and not at all for ordinary logins. There are no
// trust anchors built in: you pass in the vendor roots you decided to trust.
//
// Not done: tpm, android-key, apple, ECDAA, FIDO metadata service, revocation checks.
import crypto from 'node:crypto';
import { ALG, jwkMatchesAlg, verifySignature } from './keys.js';

export const DEFAULT_ATTESTATION_POLICY = Object.freeze({
  formats: ['none'],
  trustAnchors: [],
  requireTrustedChain: false,
  allowSelfAttestation: true,
  aaguidAllowlist: null,
  aaguidDenylist: [],
});

const KNOWN_FORMATS = ['none', 'packed', 'fido-u2f'];

// DER encoding of the OID 1.3.6.1.4.1.45724.1.1.4 (id-fido-gen-ce-aaguid)
const AAGUID_OID = Buffer.from('060b2b0601040182e51c010104', 'hex');

const fail = (reason) => ({ ok: false, reason });

function normalizeAaguid(value) {
  const hex = String(value).toLowerCase().replace(/-/g, '');
  if (!/^[0-9a-f]{32}$/.test(hex)) throw new Error(`invalid AAGUID: ${value}`);
  return hex;
}

// Accepts PEM, DER, or an already parsed certificate, so normalising a policy twice is harmless.
function toCertificate(input) {
  if (input instanceof crypto.X509Certificate) return input;
  return new crypto.X509Certificate(input);
}

// Validates the policy and fills in defaults. Throws on mistakes so they show up at startup.
export function normalizePolicy(input = {}) {
  const policy = { ...DEFAULT_ATTESTATION_POLICY, ...input };

  const badFormats = !Array.isArray(policy.formats)
    || policy.formats.length === 0
    || policy.formats.some((f) => !KNOWN_FORMATS.includes(f));
  if (badFormats) {
    throw new Error(`attestation formats must be a non-empty subset of ${KNOWN_FORMATS.join(', ')}`);
  }

  policy.trustAnchors = (policy.trustAnchors || []).map((anchor) => {
    try {
      return toCertificate(anchor);
    } catch {
      throw new Error('invalid trust anchor certificate');
    }
  });
  policy.aaguidAllowlist = policy.aaguidAllowlist ? policy.aaguidAllowlist.map(normalizeAaguid) : null;
  policy.aaguidDenylist = (policy.aaguidDenylist || []).map(normalizeAaguid);

  // The AAGUID in authData is whatever the authenticator says it is. An allowlist only means
  // something if the attestation behind it was verified, so an allowlist forces a trusted chain.
  policy.requireTrustedChain = Boolean(policy.requireTrustedChain || policy.aaguidAllowlist);
  if (policy.requireTrustedChain && policy.trustAnchors.length === 0) {
    throw new Error('requireTrustedChain / aaguidAllowlist need at least one trust anchor');
  }

  return Object.freeze(policy);
}

// Reads the AAGUID extension out of a DER certificate. Returns null when it isn't there.
// Node's X509Certificate doesn't expose arbitrary extensions, so this scans for the OID.
export function extractCertAaguid(der) {
  const at = der.indexOf(AAGUID_OID);
  if (at < 0) return null;

  let pos = at + AAGUID_OID.length;

  // optional BOOLEAN "critical" flag. The spec says it must not be set.
  if (der[pos] === 0x01 && der[pos + 1] === 0x01) {
    if (der[pos + 2] !== 0x00) throw new Error('AAGUID extension must not be critical');
    pos += 3;
  }

  // OCTET STRING (18 bytes) wrapping an OCTET STRING (16 bytes)
  const wellFormed = der[pos] === 0x04 && der[pos + 1] === 0x12
    && der[pos + 2] === 0x04 && der[pos + 3] === 0x10
    && pos + 20 <= der.length;
  if (!wellFormed) throw new Error('malformed AAGUID extension');

  return der.subarray(pos + 4, pos + 20).toString('hex');
}

function validAt(cert, now) {
  return new Date(cert.validFrom).getTime() <= now && now <= new Date(cert.validTo).getTime();
}

function subjectFields(cert) {
  const fields = {};
  for (const line of cert.subject.split('\n')) {
    const eq = line.indexOf('=');
    fields[line.slice(0, eq)] = line.slice(eq + 1);
  }
  return fields;
}

// certs[0] is the leaf and each certificate must be issued by the next one. The last one has to be
// issued by (or be) one of the trust anchors. Everything must be inside its validity period.
export function verifyChain(certs, anchors, now) {
  if (anchors.length === 0) return false;
  if (!certs.every((cert) => validAt(cert, now))) return false;

  for (let i = 0; i < certs.length - 1; i++) {
    const cert = certs[i];
    const issuer = certs[i + 1];
    if (!issuer.ca) return false;
    if (!cert.checkIssued(issuer) || !cert.verify(issuer.publicKey)) return false;
  }

  const top = certs[certs.length - 1];
  return anchors.some((anchor) => {
    if (!validAt(anchor, now)) return false;
    if (top.raw.equals(anchor.raw)) return true;
    return top.checkIssued(anchor) && top.verify(anchor.publicKey);
  });
}

function parseCertificateChain(x5c) {
  const sane = Array.isArray(x5c)
    && x5c.length > 0
    && x5c.length <= 6
    && x5c.every((c) => Buffer.isBuffer(c) && c.length < 8192);
  if (!sane) throw new Error('bad x5c');
  return x5c.map(toCertificate);
}

// Rules for a packed attestation certificate (WebAuthn spec, section 8.2.1)
function checkPackedCertificate(leaf, leafDer, authDataAaguid) {
  if (leaf.ca) return fail('bad_attestation_cert');

  const subject = subjectFields(leaf);
  const subjectOk = subject.C && subject.O && subject.CN && subject.OU === 'Authenticator Attestation';
  if (!subjectOk) return fail('bad_attestation_cert');

  const certAaguid = extractCertAaguid(leafDer);
  if (certAaguid !== null && certAaguid !== authDataAaguid) return fail('aaguid_mismatch');

  return null;
}

export function verifyAttestation({ fmt, attStmt, authDataRaw, authData, clientDataHash, credential, policy, now }) {
  if (!policy.formats.includes(fmt)) return fail('unsupported_attestation');

  const aaguid = authData.credential.aaguid.toString('hex');
  if (policy.aaguidDenylist.includes(aaguid)) return fail('aaguid_not_allowed');
  if (!(attStmt instanceof Map)) return fail('bad_attestation');

  let result;
  try {
    if (fmt === 'none') {
      if (attStmt.size !== 0) return fail('bad_attestation');
      result = { ok: true, type: 'none', trusted: null };
    } else if (fmt === 'packed') {
      result = verifyPacked({ attStmt, authDataRaw, clientDataHash, credential, aaguid, policy, now });
    } else {
      result = verifyU2f({ attStmt, authData, clientDataHash, credential, policy, now });
    }
  } catch {
    return fail('bad_attestation');
  }
  if (!result.ok) return result;

  if (policy.requireTrustedChain && result.trusted !== true) return fail('untrusted_attestation');

  // u2f authenticators have no AAGUID, so it is all zeros
  const effectiveAaguid = fmt === 'fido-u2f' ? '0'.repeat(32) : aaguid;
  if (policy.aaguidAllowlist && !policy.aaguidAllowlist.includes(effectiveAaguid)) {
    return fail('aaguid_not_allowed');
  }

  return { ok: true, info: { format: fmt, type: result.type, trusted: result.trusted, aaguid: effectiveAaguid } };
}

function verifyPacked({ attStmt, authDataRaw, clientDataHash, credential, aaguid, policy, now }) {
  const alg = attStmt.get('alg');
  const sig = attStmt.get('sig');
  const x5c = attStmt.get('x5c');

  if (attStmt.has('ecdaaKeyId')) return fail('unsupported_attestation');
  if (!Number.isInteger(alg) || !Object.values(ALG).includes(alg) || !Buffer.isBuffer(sig)) {
    return fail('bad_attestation');
  }

  const signedData = Buffer.concat([authDataRaw, clientDataHash]);

  // No certificate: the credential key signed the statement itself. Proves nothing about the vendor.
  if (x5c === undefined) {
    if (!policy.allowSelfAttestation) return fail('self_attestation_not_allowed');
    if (alg !== credential.alg) return fail('alg_mismatch');
    const good = verifySignature({ alg, jwk: credential.jwk, data: signedData, signature: sig });
    return good ? { ok: true, type: 'self', trusted: null } : fail('bad_attestation_signature');
  }

  const certs = parseCertificateChain(x5c);
  const leaf = certs[0];
  const jwk = leaf.publicKey.export({ format: 'jwk' });

  if (!jwkMatchesAlg(alg, jwk)) return fail('bad_attestation_cert');
  if (!verifySignature({ alg, jwk, data: signedData, signature: sig })) return fail('bad_attestation_signature');

  const problem = checkPackedCertificate(leaf, x5c[0], aaguid);
  if (problem) return problem;

  return { ok: true, type: 'basic', trusted: verifyChain(certs, policy.trustAnchors, now) };
}

function verifyU2f({ attStmt, authData, clientDataHash, credential, policy, now }) {
  const sig = attStmt.get('sig');
  const x5c = attStmt.get('x5c');

  if (!Buffer.isBuffer(sig) || !Array.isArray(x5c) || x5c.length !== 1) return fail('bad_attestation');
  if (credential.alg !== ALG.ES256) return fail('bad_attestation');

  const leaf = toCertificate(x5c[0]);
  const jwk = leaf.publicKey.export({ format: 'jwk' });
  if (!jwkMatchesAlg(ALG.ES256, jwk)) return fail('bad_attestation_cert');

  // u2f signs over 0x00 | rpIdHash | clientDataHash | credentialId | 0x04 | x | y
  const publicKey = Buffer.concat([
    Buffer.from([0x04]),
    Buffer.from(credential.jwk.x, 'base64url'),
    Buffer.from(credential.jwk.y, 'base64url'),
  ]);
  const signedData = Buffer.concat([
    Buffer.from([0x00]),
    authData.rpIdHash,
    clientDataHash,
    authData.credential.id,
    publicKey,
  ]);
  if (!verifySignature({ alg: ALG.ES256, jwk, data: signedData, signature: sig })) {
    return fail('bad_attestation_signature');
  }
  if (leaf.ca) return fail('bad_attestation_cert');

  return { ok: true, type: 'basic', trusted: verifyChain([leaf], policy.trustAnchors, now) };
}
