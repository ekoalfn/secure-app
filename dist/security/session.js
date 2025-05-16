"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.setupSession = exports.requireRole = exports.requireAuth = void 0;
const express_session_1 = __importDefault(require("express-session"));
const crypto_1 = __importDefault(require("crypto"));
// Generate a stronger secret key
const generateSecretKey = () => {
    return crypto_1.default.randomBytes(32).toString('hex');
};
// Konfigurasi session
const sessionConfig = {
    secret: process.env.SESSION_SECRET || generateSecretKey(),
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: process.env.NODE_ENV === 'production' || true,
        httpOnly: true,
        sameSite: 'strict',
        maxAge: 24 * 60 * 60 * 1000,
        path: '/',
    },
    name: 'secureSessionId', // Custom session name (not default)
};
// Middleware untuk mengecek session
const requireAuth = (req, res, next) => {
    var _a;
    if (!((_a = req.session) === null || _a === void 0 ? void 0 : _a.userId)) {
        return res.status(401).json({ message: 'Not authenticated' });
    }
    next();
};
exports.requireAuth = requireAuth;
// Middleware untuk mengecek role
const requireRole = (role) => {
    return (req, res, next) => {
        var _a;
        if (!((_a = req.session) === null || _a === void 0 ? void 0 : _a.userId)) {
            return res.status(401).json({ message: 'Not authenticated' });
        }
        // Type-safe role check
        const sessionWithRole = req.session;
        if (sessionWithRole.role !== role) {
            return res.status(403).json({ message: 'Not authorized' });
        }
        next();
    };
};
exports.requireRole = requireRole;
// Setup session middleware
const setupSession = (app) => {
    app.use((0, express_session_1.default)(sessionConfig));
};
exports.setupSession = setupSession;
