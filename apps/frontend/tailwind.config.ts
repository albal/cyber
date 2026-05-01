import type { Config } from "tailwindcss";

export default {
  content: ["./src/**/*.{js,ts,jsx,tsx,mdx}"],
  theme: {
    extend: {
      colors: {
        bg: "#0b0f17",
        panel: "#121826",
        border: "#1f2937",
        accent: "#34d399",
        critical: "#ef4444",
        high: "#f97316",
        medium: "#eab308",
        low: "#3b82f6",
        info: "#6b7280",
      },
    },
  },
  plugins: [],
} satisfies Config;
