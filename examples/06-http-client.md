# Calling the HTTP API

```bash
node bin/otp-cli.js gen-key >> .env      # then: export $(cat .env | xargs)
npm start
```

```bash
KEY=your-OTP_API_KEY
curl -s localhost:8080/totp/enroll -H "x-api-key: $KEY" -H 'content-type: application/json' \
  -d '{"userId":"u1","account":"you@example.com"}'
# -> { "secret": "...", "uri": "otpauth://totp/..." }   (render `uri` as a QR code)

curl -s localhost:8080/totp/confirm -H "x-api-key: $KEY" -H 'content-type: application/json' \
  -d '{"userId":"u1","code":"123456"}'
```
