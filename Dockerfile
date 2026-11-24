FROM node:22-alpine

WORKDIR /app
COPY package.json server.js store.js compliance.js ./
COPY public ./public

RUN mkdir -p /app/data && chown -R node:node /app

USER node
EXPOSE 8080
ENV PORT=8080
ENV ORBITPAY_DATA_DIR=/app/data

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:8080/healthz').then(r => process.exit(r.ok ? 0 : 1)).catch(() => process.exit(1))"

CMD ["node", "server.js"]
