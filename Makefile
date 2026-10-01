.PHONY: test check bench docker run
test:   ; npm test
check:  ; node scripts/verify-repo.js
bench:  ; node scripts/bench.js
run:    ; node bin/server.js
docker: ; docker build -f deploy/Dockerfile -t otp-fortress .
