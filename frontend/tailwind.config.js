/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        cream: {
          50: '#FBF8F3',
          100: '#F5EFE6',
          200: '#EDE3D5',
          300: '#E8DCCE',
          400: '#E1D3C5',
        },
        surface: {
          DEFAULT: '#FBF8F3',
          card: '#FBF8F3',
          muted: '#EDE3D5',
          soft: '#FAF5EE',
          border: '#E1D3C5',
        },
        brand: {
          maroon: '#641E2E',
          'maroon-deep': '#45121F',
          'maroon-secondary': '#823B4A',
          'maroon-muted': '#A66B73',
          'maroon-light': '#F7EBEF',
          text: '#302321',
          'text-muted': '#75645D',
          'text-subtle': '#96877E',
          blue: '#641E2E',
          'blue-light': '#F7EBEF',
          'blue-soft': '#EDE3D5',
          mint: '#48765C',
          'mint-light': '#EBF3EE',
          'mint-soft': '#BCD5C6',
        },
        severity: {
          urgent: '#A13D42',
          'urgent-bg': '#FBEBED',
          'urgent-border': '#F3C3C6',
          important: '#B17A37',
          'important-bg': '#FAF3E8',
          'important-border': '#EED7B8',
          attention: '#823B4A',
          'attention-bg': '#F8ECEF',
          'attention-border': '#E8CCD3',
          safe: '#48765C',
          'safe-bg': '#EBF3EE',
          'safe-border': '#BCD5C6',
        }
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', '-apple-system', 'Segoe UI', 'sans-serif'],
      },
      borderRadius: {
        '2xl': '1rem',
        '3xl': '1.5rem',
      },
      boxShadow: {
        'soft': '0 4px 20px -2px rgba(0, 0, 0, 0.05), 0 2px 6px -1px rgba(0, 0, 0, 0.03)',
        'card': '0 10px 30px -4px rgba(0, 0, 0, 0.05), 0 4px 10px -2px rgba(0, 0, 0, 0.02)',
      }
    },
  },
  plugins: [],
}
