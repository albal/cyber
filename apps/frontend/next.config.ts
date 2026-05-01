import type { NextConfig } from "next";

// API_PROXY_TARGET is the URL the Next.js server uses to reach the backend.
// In docker-compose this is `http://backend:8000`. In bare-metal dev it can
// be set to whatever the API listens on (e.g., http://localhost:8000).
const API_PROXY_TARGET = process.env.API_PROXY_TARGET ?? "http://backend:8000";

const config: NextConfig = {
  reactStrictMode: true,
  output: "standalone",

  async rewrites() {
    return [
      // Browser hits /api/* on the frontend host (same-origin, no CORS).
      // Next.js server proxies to the backend over the docker network.
      { source: "/api/:path*", destination: `${API_PROXY_TARGET}/api/:path*` },
    ];
  },
};

export default config;
