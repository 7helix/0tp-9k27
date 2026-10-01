# Build:  docker build -f deploy/Dockerfile -t otp-fortress .
FROM node:22-alpine
ENV NODE_ENV=production
WORKDIR /app
COPY package.json ./
COPY src ./src
COPY bin ./bin
RUN mkdir -p /data && chown -R node:node /data /app
USER node
EXPOSE 8080
ENV OTP_STORE_FILE=/data/store.json OTP_AUDIT_FILE=/data/audit.jsonl
HEALTHCHECK --interval=30s --timeout=3s CMD node -e "fetch('http://127.0.0.1:8080/health').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"
CMD ["node", "bin/server.js"]
