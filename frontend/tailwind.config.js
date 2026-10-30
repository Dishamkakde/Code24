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
          50: '#FDFCF7',
          100: '#FAF8F0',
          200: '#F5F2E6',
        },
        surface: {
          DEFAULT: '#FFFFFF',
          muted: '#F8F9FA',
          soft: '#F3F4F6',
          border: '#E5E7EB',
        },
        brand: {
          blue: '#2563EB',
          'blue-light': '#EFF6FF',
          'blue-soft': '#DBEAFE',
          mint: '#10B981',
          'mint-light': '#ECFDF5',
          'mint-soft': '#D1FAE5',
        },
        severity: {
          urgent: '#EF4444',
          'urgent-bg': '#FEF2F2',
          'urgent-border': '#FECACA',
          important: '#F59E0B',
          'important-bg': '#FFFBEB',
          'important-border': '#FDE68A',
          attention: '#3B82F6',
          'attention-bg': '#EFF6FF',
          'attention-border': '#BFDBFE',
          safe: '#10B981',
          'safe-bg': '#ECFDF5',
          'safe-border': '#A7F3D0',
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
