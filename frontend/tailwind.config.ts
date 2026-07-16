import type { Config } from "tailwindcss";

const config: Config = {
  content: [
    "./app/**/*.{ts,tsx}",
    "./components/**/*.{ts,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        surface: "#0b0f1a",
        panel: "#141a29",
        accent: "#4f9dff",
      },
    },
  },
  plugins: [],
};

export default config;
