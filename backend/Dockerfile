# =============================================================================
# Backend Dockerfile
# =============================================================================

FROM node:20-alpine

WORKDIR /app

# Install kubectl (needed to exec attack scripts into pods)
RUN apk add --no-cache curl && \
    curl -LO "https://dl.k8s.io/release/$(curl -sL https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl" && \
    chmod +x kubectl && mv kubectl /usr/local/bin/

COPY backend/package*.json ./
RUN npm ci --omit=dev

COPY backend/src/ ./src/
COPY scenarios/ ./scenarios/

# Data dir for SQLite
RUN mkdir -p /app/data

ENV PORT=3000
ENV NODE_ENV=production

EXPOSE 3000

USER node

CMD ["node", "src/index.js"]
