import type { Config } from 'tailwindcss'

const config: Config = {
  content: [
    './pages/**/*.{js,ts,jsx,tsx,mdx}',
    './components/**/*.{js,ts,jsx,tsx,mdx}',
    './app/**/*.{js,ts,jsx,tsx,mdx}',
  ],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        background: {
          DEFAULT: '#0B0E14',
          secondary: '#111827',
          tertiary: '#1F2937',
          landing: '#020408', // Deep darker background for hero
        },
        text: {
          primary: '#F9FAFB',
          secondary: '#9CA3AF',
          muted: '#6B7280',
        },
        accent: {
          DEFAULT: '#00F2FF',
          secondary: '#06B6D4',
          glow: 'rgba(0, 242, 255, 0.3)',
          hover: '#33F5FF', // Brighter on hover
        },
        success: '#10B981',
        warning: '#F59E0B',
        error: '#EF4444',
        glass: {
          bg: 'rgba(17, 24, 39, 0.8)',
          border: 'rgba(255, 255, 255, 0.08)',
        },
        border: 'rgba(255, 255, 255, 0.08)',
      },
      fontFamily: {
        display: ['Space Grotesk', 'sans-serif'],
        body: ['Inter', 'Outfit', 'system-ui', 'sans-serif'],
        mono: ['JetBrains Mono', 'Fira Code', 'monospace'],
      },
      backdropBlur: {
        xs: '2px',
      },
      animation: {
        'pulse-slow': 'pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite',
        'float': 'float 3s ease-in-out infinite',
      },
      keyframes: {
        float: {
          '0%, 100%': { transform: 'translateY(0px)' },
          '50%': { transform: 'translateY(-10px)' },
        },
      },
    },
  },
  plugins: [],
}

export default config
