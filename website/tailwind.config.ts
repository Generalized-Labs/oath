import type { Config } from "tailwindcss";

export default {
  darkMode: ["class"],
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        paper: "#E9E6DC",
        carbon: "#101010",
        cobalt: "#2448FF",
        hazard: "#FF4D00",
        evidence: "#B7B4AA",
      },
      fontFamily: {
        display: ["Arial Narrow", "Arial", "sans-serif"],
        mono: ["ui-monospace", "SFMono-Regular", "Consolas", "monospace"],
      },
    },
  },
  plugins: [],
} satisfies Config;
