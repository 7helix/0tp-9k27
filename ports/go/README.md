# Go port
```bash
cd ports/go && go vet ./... && go test ./...
echo "totp GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ 59000 8 SHA1" | go run ./cmd/otpf batch    # -> 94287082
```
**Status:** written to mirror `src/core` exactly, but the build environment that produced this repo had no Go toolchain, so
it has **not been compiled or run by the author**. The `ports` CI job (`.github/workflows/ports.yml`) runs `go vet`, `go test` and the
cross-language check against the Node reference on every push - treat a green job as the verification.
