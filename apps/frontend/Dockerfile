FROM node:24-alpine AS deps
WORKDIR /app
COPY package.json ./
RUN npm install --omit=optional

FROM node:24-alpine AS builder
WORKDIR /app
# Next.js inlines NEXT_PUBLIC_* at build time; runtime env is ignored.
ARG NEXT_PUBLIC_API_URL=http://localhost:8000
ENV NEXT_PUBLIC_API_URL=${NEXT_PUBLIC_API_URL}
COPY --from=deps /app/node_modules ./node_modules
COPY . .
RUN npm run build

FROM node:24-alpine AS runner
WORKDIR /app
ENV NODE_ENV=production
RUN addgroup --system --gid 10001 cyberscan \
 && adduser  --system --uid 10001 --ingroup cyberscan --home /app --shell /sbin/nologin cyberscan
COPY --from=builder --chown=cyberscan:cyberscan /app/.next/standalone ./
COPY --from=builder --chown=cyberscan:cyberscan /app/.next/static ./.next/static
COPY --from=builder --chown=cyberscan:cyberscan /app/public ./public
USER cyberscan:cyberscan
EXPOSE 3000
CMD ["node", "server.js"]
