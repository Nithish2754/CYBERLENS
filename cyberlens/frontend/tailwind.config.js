/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,jsx}",
  ],
  theme: {
    extend: {
      colors: {
        'cyber': {
          'bg-primary': '#030712',
          'bg-secondary': '#0d1117',
          'bg-tertiary': '#161b22',
          'accent-cyan': '#00d4ff',
          'accent-green': '#00ff88',
          'accent-red': '#ff0040',
          'accent-orange': '#ff6b00',
          'accent-yellow': '#ffd700',
          'accent-purple': '#7c3aed',
          'text-primary': '#e6edf3',
          'text-secondary': '#8b949e',
          'border': '#21262d',
        }
      },
      fontFamily: {
        'mono': ['JetBrains Mono', 'monospace'],
        'sans': ['Inter', 'sans-serif'],
      }
    },
  },
  plugins: [],
}
