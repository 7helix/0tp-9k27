// A software authenticator for tests: builds byte-exact WebAuthn registration/assertion responses,
// with knobs to forge every kind of bad input an attacker or buggy client could send.
import crypto from 'node:crypto';
import { encodeCbor } from '../../src/webauthn/cbor.js';
import { sha256, b64url, randomBytes } from '../../src/core/crypto-utils.js';

export class FakeAuthenticator {
  constructor({ alg = 'ES256', rpId = 'example.com', origin = 'https://example.com', uv = true, backupEligible = false } = {}) {
    Object.assign(this, { algName: alg, rpId, origin, uv, backupEligible, signCount: 0 });
    this.credId = randomBytes(32);
    if (alg === 'ES256') ({ publicKey: this.pub, privateKey: this.priv } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' }));
    else if (alg === 'EdDSA') ({ publicKey: this.pub, privateKey: this.priv } = crypto.generateKeyPairSync('ed25519'));
    else ({ publicKey: this.pub, privateKey: this.priv } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 }));
  }
  #cose() {
    const j = this.pub.export({ format: 'jwk' }); const b = (x) => Buffer.from(x, 'base64url');
    if (this.algName === 'ES256') return new Map([[1, 2], [3, -7], [-1, 1], [-2, b(j.x)], [-3, b(j.y)]]);
    if (this.algName === 'EdDSA') return new Map([[1, 1], [3, -8], [-1, 6], [-2, b(j.x)]]);
    return new Map([[1, 3], [3, -257], [-1, b(j.n)], [-2, b(j.e)]]);
  }
  #sign(data) { return this.algName === 'EdDSA' ? crypto.sign(null, data, this.priv) : crypto.sign('sha256', data, this.priv); }
  #authData({ rpId = this.rpId, flags, signCount, attested }) {
    const sc = Buffer.alloc(4); sc.writeUInt32BE(signCount);
    const parts = [sha256(rpId), Buffer.from([flags]), sc];
    if (attested) { const len = Buffer.alloc(2); len.writeUInt16BE(this.credId.length); parts.push(Buffer.alloc(16), len, this.credId, encodeCbor(this.#cose())); }
    return Buffer.concat(parts);
  }
  #baseFlags(extra = 0) { return 0x01 | (this.uv ? 0x04 : 0) | (this.backupEligible ? 0x08 : 0) | extra; }

  create(options, o = {}) {
    const clientData = Buffer.from(JSON.stringify({ type: o.type ?? 'webauthn.create', challenge: o.challenge ?? options.challenge, origin: o.origin ?? this.origin, crossOrigin: o.crossOrigin ?? false }));
    const authData = this.#authData({ rpId: o.rpId, flags: o.flags ?? this.#baseFlags(0x40), signCount: 0, attested: true });
    const attObj = encodeCbor(new Map([['fmt', o.fmt ?? 'none'], ['attStmt', new Map(o.attStmt ?? [])], ['authData', authData]]));
    return { id: b64url(this.credId), clientDataJSON: b64url(clientData), attestationObject: b64url(attObj) };
  }
  get(options, o = {}) {
    this.signCount = o.signCount ?? this.signCount + 1;
    const clientData = Buffer.from(JSON.stringify({ type: o.type ?? 'webauthn.get', challenge: o.challenge ?? options.challenge, origin: o.origin ?? this.origin, crossOrigin: false }));
    const authData = this.#authData({ rpId: o.rpId, flags: o.flags ?? this.#baseFlags(), signCount: this.signCount, attested: false });
    const signature = this.#sign(Buffer.concat([authData, sha256(clientData)]));
    if (o.corruptSignature) signature[signature.length - 1] ^= 1;
    return { id: b64url(this.credId), clientDataJSON: b64url(clientData), authenticatorData: b64url(authData), signature: b64url(signature) };
  }
}
