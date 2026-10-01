# Roadmap
- [x] WebAuthn / passkeys (attestation `none`; vendor attestation + FIDO MDS still open)
- [ ] Postgres and DynamoDB stores (must implement atomic `update`)
- [ ] QR-code SVG rendering for otpauth URIs
- [ ] Ports: Go, Java, Rust, PHP (verify with `scripts/gen-vectors.js`)
- [ ] Full RFC 6287 OCRA
- [x] Prometheus metrics endpoint
- [x] Signed audit-log checkpoints (`bin/audit-tool.js`); [ ] automated off-box publishing
Pick one, open an issue, and send a PR.
- [ ] WebAuthn: packed/TPM/Android/Apple attestation + FIDO Metadata Service, discoverable (usernameless) login
- [ ] Third-party security review + reproducible CI fuzzing corpus
- [ ] Redis/Postgres `update` conformance test-suite any store can run
