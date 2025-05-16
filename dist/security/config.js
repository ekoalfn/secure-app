"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.setupSecurity = void 0;
const helmet_1 = __importDefault(require("helmet"));
const cors_1 = __importDefault(require("cors"));
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
    origin: 'http://localhost:3000',
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-CSRF-Token'],
    credentials: true,
    maxAge: 86400 // 24 jam
};
// Konfigurasi Helmet
const helmetConfig = {
    contentSecurityPolicy: isDevelopment ? false : cspConfig,
    crossOriginEmbedderPolicy: true,
    crossOriginOpenerPolicy: true,
    crossOriginResourcePolicy: { policy: "same-site" },
    dnsPrefetchControl: true,
    frameguard: { action: 'deny' },
    hidePoweredBy: true,
    hsts: {
        maxAge: 31536000,
        includeSubDomains: true,
        preload: true
    },
    ieNoOpen: true,
    noSniff: true,
    originAgentCluster: true,
    permittedCrossDomainPolicies: { permittedPolicies: "none" },
    referrerPolicy: { policy: "strict-origin-when-cross-origin" },
    xssFilter: true
};
// Fungsi untuk mengatur keamanan aplikasi
const setupSecurity = (app) => {
    // Explicitly enable Content-Security-Policy
    app.use((0, helmet_1.default)(helmetConfig));
    // Menggunakan CORS dengan konfigurasi yang aman
    app.use((0, cors_1.default)(corsConfig));
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
        res.setHeader('Permissions-Policy', 'accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()');
        next();
    });
    // Endpoint untuk menerima CSP violation reports
    app.post('/api/security/csp-report', (req, res) => {
        console.log('CSP Violation:', req.body);
        res.status(204).end();
    });
};
exports.setupSecurity = setupSecurity;
