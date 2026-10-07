// A software authenticator for tests. It builds byte-exact WebAuthn registration and login
// responses, with options to forge every kind of bad input an attacker or a buggy client could send.
import crypto from 'node:crypto';
import { encodeCbor } from '../../src/webauthn/cbor.js';
import { sha256, b64url, randomBytes } from '../../src/core/crypto-utils.js';

const FLAG = { UP: 0x01, UV: 0x04, BE: 0x08, AT: 0x40 };
const COSE_ALG = { ES256: -7, EdDSA: -8, RS256: -257 };

const fromB64url = (text) => Buffer.from(text, 'base64url');

export class FakeAuthenticator {
  constructor({
    alg = 'ES256',
    rpId = 'example.com',
    origin = 'https://example.com',
    uv = true,
    backupEligible = false,
    aaguid = null,
  } = {}) {
    this.algName = alg;
    this.rpId = rpId;
    this.origin = origin;
    this.uv = uv;
    this.backupEligible = backupEligible;
    this.signCount = 0;

    this.aaguid = aaguid ? Buffer.from(String(aaguid).replace(/-/g, ''), 'hex') : Buffer.alloc(16);
    this.credId = randomBytes(32);

    const keys = this.#generateKeys(alg);
    this.pub = keys.publicKey;
    this.priv = keys.privateKey;
  }

  #generateKeys(alg) {
    if (alg === 'ES256') return crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
    if (alg === 'EdDSA') return crypto.generateKeyPairSync('ed25519');
    return crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  }

  // the public key in COSE form, as it goes into the attested credential data
  #coseKey() {
    const jwk = this.pub.export({ format: 'jwk' });
    if (this.algName === 'ES256') {
      return new Map([[1, 2], [3, -7], [-1, 1], [-2, fromB64url(jwk.x)], [-3, fromB64url(jwk.y)]]);
    }
    if (this.algName === 'EdDSA') {
      return new Map([[1, 1], [3, -8], [-1, 6], [-2, fromB64url(jwk.x)]]);
    }
    return new Map([[1, 3], [3, -257], [-1, fromB64url(jwk.n)], [-2, fromB64url(jwk.e)]]);
  }

  #sign(data) {
    if (this.algName === 'EdDSA') return crypto.sign(null, data, this.priv);
    return crypto.sign('sha256', data, this.priv);
  }

  #flags(extra = 0) {
    let flags = FLAG.UP | extra;
    if (this.uv) flags |= FLAG.UV;
    if (this.backupEligible) flags |= FLAG.BE;
    return flags;
  }

  #authData({ rpId = this.rpId, flags, signCount, attested }) {
    const counter = Buffer.alloc(4);
    counter.writeUInt32BE(signCount);
    const parts = [sha256(rpId), Buffer.from([flags]), counter];

    if (attested) {
      const idLength = Buffer.alloc(2);
      idLength.writeUInt16BE(this.credId.length);
      parts.push(this.aaguid, idLength, this.credId, encodeCbor(this.#coseKey()));
    }
    return Buffer.concat(parts);
  }

  // Builds an attestation statement. `spec` is
  //   { kind: 'packed' | 'packed-self' | 'fido-u2f', certKey, x5c: [DER...], corruptSig, statementAlg }
  #attestation(spec, authData, clientDataHash) {
    const maybeCorrupt = (signature) => {
      if (spec.corruptSig) signature[signature.length - 1] ^= 1;
      return signature;
    };

    if (spec.kind === 'packed-self') {
      const alg = spec.statementAlg ?? COSE_ALG[this.algName];
      const signature = maybeCorrupt(this.#sign(Buffer.concat([authData, clientDataHash])));
      return { fmt: 'packed', attStmt: new Map([['alg', alg], ['sig', signature]]) };
    }

    if (spec.kind === 'packed') {
      const signature = maybeCorrupt(crypto.sign('sha256', Buffer.concat([authData, clientDataHash]), spec.certKey));
      return { fmt: 'packed', attStmt: new Map([['alg', -7], ['sig', signature], ['x5c', spec.x5c]]) };
    }

    // fido-u2f signs over 0x00 | rpIdHash | clientDataHash | credentialId | 0x04 | x | y
    const jwk = this.pub.export({ format: 'jwk' });
    const publicKey = Buffer.concat([Buffer.from([4]), fromB64url(jwk.x), fromB64url(jwk.y)]);
    const signedData = Buffer.concat([Buffer.from([0]), sha256(this.rpId), clientDataHash, this.credId, publicKey]);
    const signature = maybeCorrupt(crypto.sign('sha256', signedData, spec.certKey));
    return { fmt: 'fido-u2f', attStmt: new Map([['sig', signature], ['x5c', spec.x5c]]) };
  }

  // Registration. `overrides` can change the challenge, origin, type, rpId, flags, or the attestation.
  create(options, overrides = {}) {
    const clientData = Buffer.from(JSON.stringify({
      type: overrides.type ?? 'webauthn.create',
      challenge: overrides.challenge ?? options.challenge,
      origin: overrides.origin ?? this.origin,
      crossOrigin: overrides.crossOrigin ?? false,
    }));

    const authData = this.#authData({
      rpId: overrides.rpId,
      flags: overrides.flags ?? this.#flags(FLAG.AT),
      signCount: 0,
      attested: true,
    });

    let fmt = overrides.fmt ?? 'none';
    let attStmt = new Map(overrides.attStmt ?? []);
    if (overrides.attestation) {
      ({ fmt, attStmt } = this.#attestation(overrides.attestation, authData, sha256(clientData)));
    }

    const attestationObject = encodeCbor(new Map([['fmt', fmt], ['attStmt', attStmt], ['authData', authData]]));
    return {
      id: b64url(this.credId),
      clientDataJSON: b64url(clientData),
      attestationObject: b64url(attestationObject),
    };
  }

  // Login. Same overrides, plus signCount and corruptSignature.
  get(options, overrides = {}) {
    this.signCount = overrides.signCount ?? this.signCount + 1;

    const clientData = Buffer.from(JSON.stringify({
      type: overrides.type ?? 'webauthn.get',
      challenge: overrides.challenge ?? options.challenge,
      origin: overrides.origin ?? this.origin,
      crossOrigin: false,
    }));

    const authData = this.#authData({
      rpId: overrides.rpId,
      flags: overrides.flags ?? this.#flags(),
      signCount: this.signCount,
      attested: false,
    });

    const signature = this.#sign(Buffer.concat([authData, sha256(clientData)]));
    if (overrides.corruptSignature) signature[signature.length - 1] ^= 1;

    return {
      id: b64url(this.credId),
      clientDataJSON: b64url(clientData),
      authenticatorData: b64url(authData),
      signature: b64url(signature),
    };
  }
}
