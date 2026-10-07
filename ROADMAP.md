# Roadmap
- [x] WebAuthn / passkeys (attestation `none`; vendor attestation + FIDO MDS still open)
- [x] Postgres store + shared conformance suite; [ ] DynamoDB store
- [ ] QR-code SVG rendering for otpauth URIs
- [x] Ports: Java, Go, Python; [ ] Rust, PHP, C#, Ruby (add to `scripts/cross-check.js`)
- [ ] Full RFC 6287 OCRA
- [x] Prometheus metrics endpoint
- [x] Signed audit-log checkpoints (`bin/audit-tool.js`); [ ] automated off-box publishing
- [x] WebAuthn packed + fido-u2f attestation; [ ] TPM / Android-key / Apple attestation, FIDO Metadata Service, discoverable (usernameless) login
- [ ] Third-party security review + reproducible CI fuzzing corpus

Pick one, open an issue, and send a PR.
