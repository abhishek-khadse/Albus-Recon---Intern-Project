/** @type {import('tailwindcss').Config} */
module.exports = {
  darkMode: 'class', // Enable dark mode using class strategy
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        // Custom dark theme colors
        dark: {
          DEFAULT: '#1a202c',
          light: '#2d3748',
          lighter: '#4a5568',
        },
      },
    },
  },
  plugins: [],
}
