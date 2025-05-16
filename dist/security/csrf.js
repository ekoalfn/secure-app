"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.synchronizerToken = exports.doubleSubmitCookie = exports.refreshCsrfToken = exports.getCSRFToken = exports.validateCsrfToken = exports.sendCsrfToken = exports.csrfMiddleware = exports.validateCSRFToken = exports.generateCSRFToken = void 0;
const crypto_1 = __importDefault(require("crypto"));
const csurf_1 = __importDefault(require("csurf"));
const errorHandler_1 = require("./errorHandler");
// Simpan CSRF token dalam memory (dalam production gunakan Redis/database)
const csrfTokens = new Map();
// Cleanup expired tokens regularly
setInterval(() => {
    const now = Date.now();
    for (const [userId, data] of csrfTokens.entries()) {
        if (now > data.expires) {
            csrfTokens.delete(userId);
        }
    }
}, 60 * 60 * 1000); // Clean up every hour
// Generate CSRF token with improved entropy
const generateCSRFToken = (userId) => {
    const token = crypto_1.default.randomBytes(64).toString('hex');
    const expires = Date.now() + 1 * 60 * 60 * 1000; // 1 hour expiration (shorter is better)
    csrfTokens.set(userId, { token, expires });
    return token;
};
exports.generateCSRFToken = generateCSRFToken;
// Validasi CSRF token with constant-time comparison
const validateCSRFToken = (userId, token) => {
    const stored = csrfTokens.get(userId);
    if (!stored)
        return false;
    // Cek expired
    if (Date.now() > stored.expires) {
        csrfTokens.delete(userId);
        return false;
    }
    // Use constant-time comparison to prevent timing attacks
    try {
        return crypto_1.default.timingSafeEqual(Buffer.from(stored.token, 'utf-8'), Buffer.from(token, 'utf-8'));
    }
    catch (e) {
        return false;
    }
};
exports.validateCSRFToken = validateCSRFToken;
// Konfigurasi CSRF
const csrfOptions = {
    cookie: {
        httpOnly: true,
        secure: true,
        sameSite: 'strict',
        path: '/',
        maxAge: 3600 // 1 hour expiration
    }
};
// Create a type-safe wrapper for csurf middleware
const csurfMiddleware = (0, csurf_1.default)(csrfOptions);
// Middleware untuk CSRF protection
const csrfMiddleware = (req, res, next) => {
    // Skip CSRF check untuk GET, HEAD, OPTIONS requests
    if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) {
        return next();
    }
    // Check for proper origin header to prevent CSRF
    const origin = req.headers.origin;
    const host = req.headers.host;
    if (origin && host) {
        // For production use a whitelist of allowed origins
        const allowedOrigins = ['https://localhost:3000']; // Add your domains
        try {
            const originHostname = new URL(origin).hostname;
            const requestHostname = host.split(':')[0];
            if (originHostname !== requestHostname && !allowedOrigins.includes(origin)) {
                return next(new errorHandler_1.AppError('Invalid origin', 403));
            }
        }
        catch (e) {
            return next(new errorHandler_1.AppError('Invalid origin format', 403));
        }
    }
    // Safely apply CSRF protection with error handling
    try {
        // Type cast to avoid TypeScript errors
        const typeSafeReq = req;
        const typeSafeRes = res;
        csurfMiddleware(typeSafeReq, typeSafeRes, (err) => {
            if (err) {
                return next(new errorHandler_1.AppError('Invalid CSRF token', 403));
            }
            next();
        });
    }
    catch (e) {
        return next(new errorHandler_1.AppError('CSRF validation error', 403));
    }
};
exports.csrfMiddleware = csrfMiddleware;
// Middleware untuk mengirim CSRF token ke client
const sendCsrfToken = (req, res, next) => {
    // Set CSRF token di header if the function exists
    if (typeof req.csrfToken === 'function') {
        res.setHeader('X-CSRF-Token', req.csrfToken());
    }
    next();
};
exports.sendCsrfToken = sendCsrfToken;
// Middleware untuk validasi CSRF token
const validateCsrfToken = (req, res, next) => {
    var _a;
    const token = req.headers['x-csrf-token'];
    const sessionToken = (_a = req.session) === null || _a === void 0 ? void 0 : _a.csrfToken;
    if (!token || !sessionToken) {
        return next(new errorHandler_1.AppError('Missing CSRF token', 403));
    }
    try {
        // Use constant-time comparison to prevent timing attacks
        const isValid = crypto_1.default.timingSafeEqual(Buffer.from(token.toString(), 'utf-8'), Buffer.from(sessionToken, 'utf-8'));
        if (!isValid) {
            return next(new errorHandler_1.AppError('Invalid CSRF token', 403));
        }
    }
    catch (err) {
        return next(new errorHandler_1.AppError('Invalid CSRF token', 403));
    }
    next();
};
exports.validateCsrfToken = validateCsrfToken;
// CSRF token endpoint handler
const getCSRFToken = (req, res) => {
    if (!req.session || !req.session.userId) {
        return res.status(401).json({ message: 'Unauthorized' });
    }
    const token = (0, exports.generateCSRFToken)(req.session.userId);
    if (req.session) {
        req.session.csrfToken = token;
    }
    res.json({ csrfToken: token });
};
exports.getCSRFToken = getCSRFToken;
// Middleware untuk refresh CSRF token
const refreshCsrfToken = (req, res, next) => {
    // Generate token baru
    if (req.csrfToken) {
        const newToken = req.csrfToken();
        // Update token di session
        if (req.session) {
            req.session.csrfToken = newToken;
        }
        // Set token baru di header
        res.setHeader('X-CSRF-Token', newToken);
    }
    next();
};
exports.refreshCsrfToken = refreshCsrfToken;
// Middleware untuk double submit cookie pattern
const doubleSubmitCookie = (req, res, next) => {
    // Generate random token
    const token = Math.random().toString(36).substring(2);
    // Set token di cookie
    res.cookie('XSRF-TOKEN', token, {
        httpOnly: false,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict'
    });
    // Set token di header
    res.setHeader('X-CSRF-Token', token);
    next();
};
exports.doubleSubmitCookie = doubleSubmitCookie;
// Middleware untuk synchronizer token pattern
const synchronizerToken = (req, res, next) => {
    // Generate random token
    const token = Math.random().toString(36).substring(2);
    // Simpan token di session
    if (req.session) {
        req.session.csrfToken = token;
    }
    // Set token di header
    res.setHeader('X-CSRF-Token', token);
    next();
};
exports.synchronizerToken = synchronizerToken;
