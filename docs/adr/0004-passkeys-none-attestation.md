# ADR 0004 - WebAuthn: attestation "none", three algorithms, no MDS
**Status:** accepted; **extended by [ADR 0008](0008-attestation-trust-is-policy.md)** (packed / fido-u2f + trust anchors, default unchanged). **Context:** consumer passkey managers send `none` attestation; vendor attestation formats (packed, TPM, android-key, apple) each need certificate-chain validation and FIDO Metadata Service data.
**Decision:** accept `none` only; support ES256/EdDSA/RS256; reject everything else explicitly (`unsupported_attestation`, `alg_not_allowed`).
**Consequences:** works with every mainstream authenticator and stays small and reviewable; cannot restrict logins to specific hardware models. Adding attestation later must not change stored credential format.

**Update:** `packed` and `fido-u2f` attestation with operator-supplied trust anchors were added later - see ADR 0008. The default policy is still `none` only.
