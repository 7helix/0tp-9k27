// COSE public keys and signature checking, shared by registration, login and attestation.
import crypto from 'node:crypto';
import { b64url } from '../core/crypto-utils.js';

export const ALG = { ES256: -7, EdDSA: -8, RS256: -257 };

// COSE key (a CBOR map with integer keys) to a JWK that node:crypto can load.
export function coseToJwk(cose) {
  if (!(cose instanceof Map)) throw new Error('COSE key must be a map');

  const kty = cose.get(1);
  const alg = cose.get(3);

  const bytesParam = (label, length) => {
    const value = cose.get(label);
    if (!Buffer.isBuffer(value) || (length && value.length !== length)) {
      throw new Error('bad COSE parameter');
    }
    return value;
  };

  if (alg === ALG.ES256 && kty === 2 && cose.get(-1) === 1) {
    const jwk = { kty: 'EC', crv: 'P-256', x: b64url(bytesParam(-2, 32)), y: b64url(bytesParam(-3, 32)) };
    return { alg, jwk };
  }

  if (alg === ALG.EdDSA && kty === 1 && cose.get(-1) === 6) {
    return { alg, jwk: { kty: 'OKP', crv: 'Ed25519', x: b64url(bytesParam(-2, 32)) } };
  }

  if (alg === ALG.RS256 && kty === 3) {
    const modulus = bytesParam(-1);
    if (modulus.length < 256) throw new Error('RSA key below 2048 bits');
    return { alg, jwk: { kty: 'RSA', n: b64url(modulus), e: b64url(bytesParam(-2)) } };
  }

  throw new Error('unsupported COSE key');
}

// An ES256 signature has to come from a P-256 key and so on. Stops a mismatched alg/key pairing.
export function jwkMatchesAlg(alg, jwk) {
  if (alg === ALG.ES256) return jwk.kty === 'EC' && jwk.crv === 'P-256';
  if (alg === ALG.EdDSA) return jwk.kty === 'OKP' && jwk.crv === 'Ed25519';
  if (alg === ALG.RS256) return jwk.kty === 'RSA';
  return false;
}

export function verifySignature({ alg, jwk, data, signature }) {
  try {
    // createPublicKey also rejects EC points that aren't on the curve
    const key = crypto.createPublicKey({ key: jwk, format: 'jwk' });
    if (alg === ALG.EdDSA) return crypto.verify(null, data, key, signature);
    if (alg === ALG.ES256 || alg === ALG.RS256) return crypto.verify('sha256', data, key, signature);
  } catch {
    // bad key or signature encoding: treat as a failed check
  }
  return false;
}
