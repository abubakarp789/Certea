# CyberSign Frontend

Modern, professional Next.js frontend for the CyberSign Digital Signature Validator.

## Features

- **Modern UI/UX**: Built with Next.js 14, React, and Tailwind CSS
- **Dark Theme**: Cybersecurity-focused dark theme with glassmorphism effects
- **Fully Responsive**: Mobile-first design that works on all devices
- **Type-Safe**: Built with TypeScript for better developer experience
- **Animated**: Smooth animations using Framer Motion
- **Accessible**: WCAG 2.1 AA compliant with keyboard navigation

## Pages

- **Dashboard**: Overview with system stats and feature cards
- **Key Generator**: Generate RSA key pairs (2048/4096 bits)
- **Sign Text**: Create digital signatures for text messages
- **Verify Text**: Verify text message signatures
- **Sign File**: Sign any file type (PDF, images, etc.)
- **Verify File**: Verify file integrity using signatures
- **Certificate Authority**: Create CA, issue certificates, verify certificates
- **Audit Logs**: View and export verification history

## Tech Stack

- **Framework**: Next.js 14 (App Router)
- **Language**: TypeScript
- **Styling**: Tailwind CSS
- **Animations**: Framer Motion
- **Icons**: Lucide React
- **Forms**: React Hook Form
- **Validation**: Zod

## Getting Started

### Prerequisites

- Node.js 18+ and npm
- Python backend running on http://localhost:8000

### Installation

```bash
cd frontend
npm install
```

### Development

```bash
npm run dev
```

Open [http://localhost:3000](http://localhost:3000) in your browser.

### Build

```bash
npm run build
npm start
```

### Lint

```bash
npm run lint
```

## Environment Variables

Create a `.env.local` file in the root:

```env
NEXT_PUBLIC_API_URL=http://localhost:8000
```

## API Integration

The frontend connects to the existing Python backend through:

1. **Next.js Rewrites**: API requests to `/api/*` are proxied to the Python backend
2. **CORS**: Backend configured to allow requests from the frontend

## Architecture

```
frontend/
├── app/                    # Next.js App Router pages
│   ├── layout.tsx         # Root layout
│   ├── page.tsx           # Dashboard
│   ├── generate/           # Key Generator
│   ├── sign-text/         # Sign Text
│   ├── verify-text/       # Verify Text
│   ├── sign-file/         # Sign File
│   ├── verify-file/       # Verify File
│   ├── certificate-authority/ # Certificate Authority
│   ├── audit-logs/        # Audit Logs
│   └── globals.css        # Global styles
├── components/
│   ├── layout/            # Layout components
│   │   ├── Sidebar.tsx
│   │   ├── Header.tsx
│   │   └── Layout.tsx
│   ├── ui/                # Reusable UI components
│   │   ├── Toast.tsx
│   │   ├── Button.tsx
│   │   └── ...
│   ├── dashboard/         # Dashboard components
│   ├── crypto/            # Cryptography components
│   └── audit/             # Audit components
├── lib/
│   ├── api.ts             # API client
│   ├── utils.ts           # Utility functions
│   └── types.ts           # TypeScript types
└── hooks/
    ├── useToast.ts         # Toast notification hook
    └── useLocalStorage.ts  # Local storage hooks
```

## Design System

### Colors

- **Background**: #0B0E14 (dark blue-black)
- **Accent**: #00F2FF (cyan)
- **Success**: #10B981 (green)
- **Error**: #EF4444 (red)
- **Warning**: #F59E0B (amber)

### Typography

- **Display**: Space Grotesk (headings)
- **Body**: Inter (body text)
- **Mono**: JetBrains Mono (code, keys)

### Components

All components use:
- Tailwind CSS for styling
- Glassmorphism effects
- Smooth hover transitions
- Keyboard navigation
- Accessibility attributes

## Deployment

### Vercel (Recommended)

1. Push code to GitHub
2. Import project in Vercel
3. Set `NEXT_PUBLIC_API_URL` environment variable
4. Deploy

### Docker

```dockerfile
FROM node:18-alpine
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY . .
RUN npm run build
EXPOSE 3000
CMD ["npm", "start"]
```

### Nginx Reverse Proxy

```nginx
server {
    listen 80;
    server_name cybersign.com;

    # Frontend (Next.js)
    location / {
        proxy_pass http://localhost:3000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_cache_bypass $http_upgrade;
    }

    # Backend API
    location /api/ {
        proxy_pass http://localhost:8000;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

## Contributing

1. Create a feature branch
2. Make your changes
3. Run tests and lint
4. Submit a pull request

## License

ISC
