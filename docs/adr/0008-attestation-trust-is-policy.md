# ADR 0008 - Attestation trust anchors are configuration, never bundled
**Status:** accepted. **Context:** "which vendors do we trust" is a business and security decision that changes over time; shipping a root list would make this library
the silent arbiter and a stale-root liability. **Decision:** no built-in anchors; an AAGUID allowlist implies a required trusted chain; startup validation rejects policies that
demand trust without anchors. **Consequences:** more setup for users who want hardware restrictions; users who do not (the default `none`) are unaffected.
The AAGUID inside `authData` is attacker-controlled unless the attestation is verified, so `none` and self attestation are never reported as trusted and can never satisfy an allowlist. The default policy stays `none` only.
