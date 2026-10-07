# WebAuthn attestation: restricting *which authenticators* may enrol

Attestation answers one question at **registration** time: *"is this new key stored in an authenticator made by a vendor I trust?"*
It does not make logins stronger and it is not needed for ordinary consumer passkeys. Use it for regulated or high-assurance
deployments ("FIPS-certified security keys only", "company-issued keys only").

## Formats supported
| Format | What it proves | Trust |
|---|---|---|
| `none` (default) | nothing - the authenticator declined to attest | n/a |
| `packed` + certificate (`x5c`) | the credential was created by a device holding the vendor's attestation key | **trusted only if the chain reaches a root YOU configure** |
| `packed` self attestation | the credential key signed its own statement | never "trusted" - proves nothing about the vendor |
| `fido-u2f` | same as packed-certificate, for legacy U2F keys (ES256 only, AAGUID is all zeros) | as packed |
Not implemented: `tpm`, `android-key`, `android-safetynet`, `apple`, ECDAA, FIDO Metadata Service download/status checks, revocation (CRL/OCSP).

## Policy
```js
new WebAuthn({ store, rpId, origins, attestation: {
  formats: ['packed', 'fido-u2f'],          // default ['none']
  trustAnchors: [vendorRootPem],            // YOU supply roots; none are bundled
  requireTrustedChain: true,                // reject anything that does not chain to an anchor
  aaguidAllowlist: ['ee882879-721c-4913-9775-3dfcce97072a'],   // implies requireTrustedChain
  aaguidDenylist: [],                       // always enforced (but see caveat)
  allowSelfAttestation: false,
}});
```
Misconfiguration throws at construction (unknown format, bad PEM, malformed AAGUID, `requireTrustedChain` without anchors).
Env equivalents: see `.env.example` (`OTP_WEBAUTHN_*`).

## What is checked (packed with certificate)
1. `alg` supported and the leaf's key type matches it (an ES256 statement needs a P-256 key). 2. Signature over `authData || SHA-256(clientDataJSON)`.
3. Certificate profile: not a CA; subject has `C`, `O`, `CN` and `OU = "Authenticator Attestation"`. 4. If the cert carries the AAGUID extension
(`1.3.6.1.4.1.45724.1.1.4`) it must equal the AAGUID in `authData` and must not be marked critical. 5. Chain: every certificate valid *now*, each issued
by the next, intermediates are CAs, and the top is issued by (or equals) a configured anchor.

## Why the allowlist forces a trusted chain
The AAGUID in `authData` is **self-asserted**: with `none` or self attestation an attacker simply claims whatever model you allow.
So an allowlist is only meaningful on top of a verified chain, and the code enforces that (`normalizePolicy`, tested, and in `npm run mutation`).
The denylist is best-effort for the same reason.

## Getting trust anchors
Use the vendor's published attestation roots or the FIDO Metadata Service (download and verify the MDS blob yourself - not automated here),
keep them in a PEM bundle, review it like any other trust store, and rotate it when vendors do. Revocation is not checked.

## Privacy
Attestation reveals the authenticator model to your server (and "direct" attestation prompts users in some browsers). For consumer apps keep `none`.

## How it is tested
`tests/attestation.test.js` builds real X.509 chains with the `openssl` CLI (root, optional intermediate, leaf with AAGUID extension) and a software
authenticator that can forge every failure: wrong OU, CA leaf, critical extension, AAGUID mismatch, corrupted/foreign signatures, expired and not-yet-valid
certificates, untrusted roots, self-attestation with a wrong algorithm, junk statements. **Not tested:** real security keys or vendor roots.
