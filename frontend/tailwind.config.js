/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,jsx}'],
  theme: {
    extend: {
      colors: {
        surface: '#07111f',
        panel: '#0d1b2d',
        line: '#1e3550',
        accent: '#42d3a3',
      },
    },
  },
  plugins: [],
};
