import helmet from 'helmet';
import cors from 'cors';
import { Express } from 'express';

// Determine if we're in development mode
const isDevelopment = process.env.NODE_ENV === 'development';

// Konfigurasi CSP (Content Security Policy)
const cspConfig = {
  directives: {
    defaultSrc: ["'self'"],
    scriptSrc: ["'self'", ...(isDevelopment ? ["'unsafe-inline'", "'unsafe-eval'"] : [])],
    styleSrc: ["'self'", ...(isDevelopment ? ["'unsafe-inline'"] : [])],
    imgSrc: ["'self'", "data:"],
    connectSrc: ["'self'", ...(isDevelopment ? ["ws:", "wss:"] : [])],
    fontSrc: ["'self'"],
    objectSrc: ["'none'"],
    mediaSrc: ["'self'"],
    frameSrc: ["'none'"],
    baseUri: ["'self'"],
    formAction: ["'self'"],
    frameAncestors: ["'none'"],
    upgradeInsecureRequests: [],
    reportUri: '/api/security/csp-report'
  }
};

// Konfigurasi CORS - limit to specific origin rather than wildcard
const corsConfig = {
  origin: 'http://localhost:3000', // Set to specific origins instead of '*'
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-CSRF-Token'],
  credentials: true,
  maxAge: 86400 // 24 jam
};

// Konfigurasi Helmet
const helmetConfig = {
  contentSecurityPolicy: isDevelopment ? false : cspConfig, // Disable CSP in development
  crossOriginEmbedderPolicy: true,
  crossOriginOpenerPolicy: true,
  crossOriginResourcePolicy: { policy: "same-site" as const },
  dnsPrefetchControl: true,
  frameguard: { action: 'deny' as const }, // Prevent clickjacking
  hidePoweredBy: true,
  hsts: {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true
  },
  ieNoOpen: true,
  noSniff: true,
  originAgentCluster: true,
  permittedCrossDomainPolicies: { permittedPolicies: "none" as const },
  referrerPolicy: { policy: "strict-origin-when-cross-origin" as const },
  xssFilter: true
};

// Fungsi untuk mengatur keamanan aplikasi
export const setupSecurity = (app: Express) => {
  // Explicitly enable Content-Security-Policy
  app.use(helmet(helmetConfig));

  // Menggunakan CORS dengan konfigurasi yang aman
  app.use(cors(corsConfig));

  // Mengatur header keamanan tambahan
  app.use((req, res, next) => {
    // Mencegah clickjacking dengan X-Frame-Options
    res.setHeader('X-Frame-Options', 'DENY');
    
    // Mencegah XSS
    res.setHeader('X-XSS-Protection', '1; mode=block');
    
    // Mencegah MIME type sniffing
    res.setHeader('X-Content-Type-Options', 'nosniff');
    
    // Mengatur referrer policy
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    
    // Mengatur permissions policy
    res.setHeader('Permissions-Policy', 
      'accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()'
    );
    
    next();
  });

  // Endpoint untuk menerima CSP violation reports
  app.post('/api/security/csp-report', (req, res) => {
    console.log('CSP Violation:', req.body);
    res.status(204).end();
  });
}; 