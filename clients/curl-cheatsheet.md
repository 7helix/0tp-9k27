# curl cheatsheet
```bash
export KEY=your-api-key H='content-type: application/json'
curl -s localhost:8080/otp/send      -H "x-api-key: $KEY" -H "$H" -d '{"userId":"u1","channel":"email","to":"me@example.com"}'
curl -s localhost:8080/otp/verify    -H "x-api-key: $KEY" -H "$H" -d '{"userId":"u1","code":"123456"}'
curl -s localhost:8080/totp/enroll   -H "x-api-key: $KEY" -H "$H" -d '{"userId":"u1","account":"me@example.com"}'
curl -s localhost:8080/totp/confirm  -H "x-api-key: $KEY" -H "$H" -d '{"userId":"u1","code":"123456"}'
curl -s localhost:8080/totp/verify   -H "x-api-key: $KEY" -H "$H" -d '{"userId":"u1","code":"123456"}'
curl -s localhost:8080/backup/generate -H "x-api-key: $KEY" -H "$H" -d '{"userId":"u1"}'
curl -s localhost:8080/backup/verify -H "x-api-key: $KEY" -H "$H" -d '{"userId":"u1","code":"ABCDE-FGHJK"}'
```
