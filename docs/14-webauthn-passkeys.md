# WebAuthn / passkeys (the phishing-resistant option)

**Why it beats every OTP here:** the browser puts the page's *origin* inside the signed data. A look-alike domain can
ask for a signature but the result is bound to `https://evil.example`, so your server rejects it. Nothing typed, nothing relayable.

## Flow
```
register:  start  -> options {challenge, rp, user(handle), pubKeyCredParams}
           browser: navigator.credentials.create(options)  ->  {id, clientDataJSON, attestationObject}
           finish -> server verifies and stores {credentialId, publicKey, signCount}
login:     start  -> options {challenge, allowCredentials}
           browser: navigator.credentials.get(options)     ->  {id, clientDataJSON, authenticatorData, signature}
           finish -> server verifies signature over authenticatorData || SHA-256(clientDataJSON)
```
Browser side: base64url-decode `challenge`/ids before calling the API and base64url-encode the ArrayBuffers you send back.

## What `src/webauthn/webauthn.js` verifies
| Check | Stops |
|---|---|
| `clientData.type` is `webauthn.create` / `webauthn.get` | using a registration blob as a login |
| challenge equals the one we issued (single-use, 5 min) | replay, pre-computed responses |
| `origin` is in your allowlist, `crossOrigin` is not true | **phishing**, malicious iframes |
| `rpIdHash == SHA-256(rpId)` | credentials from another site |
| UP flag (and UV flag when `requireUV`) | "touch-less" or PIN-less use |
| signature (ES256, EdDSA, RS256 >= 2048-bit) | forged assertions |
| signature counter strictly increases (when the device has one) | **cloned authenticators** |
| credential id can only belong to one account | credential re-binding |

## Design decisions & limits
- **Attestation:** default `none` (what consumer passkey managers send). `packed` and `fido-u2f` with trust anchors and AAGUID allowlists are supported - see [19](19-webauthn-attestation.md). TPM / Android-key / Apple formats and FIDO MDS are not implemented.
- Synced passkeys report counter `0` forever; that is accepted. `backupEligible/backedUp` flags are stored so you can apply policy.
- The `user.id` handle is 32 random bytes - never an email or database id.
- `no_credentials` from `startAuthentication` reveals whether an account has passkeys; hide that behind a uniform response if enumeration matters to you.
- Discoverable-credential ("usernameless") login is not included; `startAuthentication` needs a `userId`.
- Tested with a software authenticator (`tests/helpers/fake-authenticator.js`) - real browsers and security keys are the final judge.
