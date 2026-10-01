# Splitting the master key (Shamir's Secret Sharing)

`OTP_MASTER_KEY` decrypts every TOTP seed. Put it in one place and that place is your single point of failure (and of theft).
Shamir splits it into **N** shares where any **K** reconstruct it and **K-1 reveal nothing** (information-theoretic, not just "hard").

```js
import { shamir } from './src/index.js';
const { shares, fingerprint } = shamir.split(masterKey, 5, 3);   // give 5 people/vaults a share; any 3 can recover
const key = shamir.combine([shares[0], shares[3], shares[4]], { fingerprint });
```
Share format `SSS1-<k>-<x>-<data>-<checksum>`: the checksum catches typos; the fingerprint (first 64 bits of SHA-256 of the key;
store it with the ceremony notes, it does not help an attacker) catches wrong or malicious shares at recovery time.

## Ceremony checklist
- [ ] Generate the key on an offline machine; split there; never write the whole key to disk or chat.
- [ ] Shares go to different people, different media (password manager, safe, HSM card), different places.
- [ ] Record N, K and the fingerprint in the runbook (not the shares).
- [ ] Rehearse recovery twice a year; replace shares when staff leave.
- [ ] The running server still needs the key in memory/KMS - Shamir protects **custody and recovery**, not runtime exposure.

## Caveats
Plain Shamir does not authenticate shares (a malicious holder can submit a bad one - the fingerprint detects it, not which one).
Use a vetted tool for regulated environments; this implementation is tested (uniformity, any-K-of-N, tamper cases) but not audited.
